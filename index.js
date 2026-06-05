'use strict';

const crypto = require('crypto');

const ydbMod = require('ydb-sdk');
let driverPromise = null;

const CFG = {
  endpoint: process.env.YDB_ENDPOINT || '',
  database: process.env.YDB_DATABASE || '',
  prefix: process.env.YDB_TABLE_PREFIX || 'vi3_',
  adminSecret: process.env.ADMIN_SECRET || '',
  corsOrigins: String(process.env.CORS_ORIGINS || 'https://vi3na1bita.website.yandexcloud.net,https://apel-s-in.github.io')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean),
  presenceTtlMs: num(process.env.PRESENCE_TTL_MS, 120000),
  friendInviteTtlMs: num(process.env.FRIEND_INVITE_TTL_MS, 604800000),
  gameInviteTtlMs: num(process.env.GAME_INVITE_TTL_MS, 30000),
  roomTtlMs: num(process.env.ROOM_TTL_MS, 86400000),
  signalTtlMs: num(process.env.SIGNAL_TTL_MS, 600000),
  nearbyTtlMs: num(process.env.NEARBY_TTL_MS, 300000),
  vapidPublicKey: safe(process.env.VAPID_PUBLIC_KEY || ''),
  turnUrls: String(process.env.TURN_URLS || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean),
  turnUsername: safe(process.env.TURN_USERNAME || ''),
  turnCredential: safe(process.env.TURN_CREDENTIAL || ''),
  turnDisabled: safe(process.env.TURN_DISABLED || '1') === '1',
  webPushFunctionUrl: safe(process.env.WEBPUSH_FUNCTION_URL || ''),
  webPushSecret: safe(process.env.WEBPUSH_SECRET || '')
};

const TABLE = `${CFG.prefix}kv`;

function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function safe(v) {
  return String(v == null ? '' : v).trim();
}

function now() {
  return Date.now();
}

function rid(prefix = 'id') {
  return `${prefix}_${now().toString(36)}_${crypto.randomBytes(6).toString('hex')}`;
}

function hash(v) {
  return crypto.createHash('sha256').update(String(v || ''), 'utf8').digest('hex');
}

function publicIpHash(event) {
  const h = event.headers || {};
  const raw = safe(h['x-forwarded-for'] || h['X-Forwarded-For'] || h['x-real-ip'] || h['X-Real-Ip'] || '');
  const ip = raw.split(',')[0].trim();
  return ip ? hash(`ip:${ip}`).slice(0, 32) : '';
}

function parseBody(event) {
  if (!event || typeof event !== 'object') return {};

  if (!event.body && (event.action || event.mode || event.adminSecret || event.playerId || event.userId)) {
    return event;
  }

  if (!event.body) return {};

  const text = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf8') : String(event.body);
  try {
    return JSON.parse(text || '{}') || {};
  } catch {
    return {};
  }
}

function corsHeaders(event) {
  const h = event.headers || {};
  const origin = safe(h.origin || h.Origin || '');
  const reqHeaders = safe(h['access-control-request-headers'] || h['Access-Control-Request-Headers'] || '');
  let allow = '*';

  if (origin === 'null') {
    allow = 'null';
  } else if (CFG.corsOrigins.includes('*')) {
    allow = '*';
  } else if (CFG.corsOrigins.includes(origin)) {
    allow = origin;
  } else {
    allow = CFG.corsOrigins[0] || '*';
  }

  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': reqHeaders || 'Content-Type, Accept, Authorization, X-Requested-With, X-Vi3-Player, X-Vi3-Secret, X-Vi3-Admin',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function reply(event, statusCode, body) {
  return {
    statusCode,
    headers: {
      ...corsHeaders(event),
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    },
    body: JSON.stringify(body)
  };
}

function sanitizeId(v, max = 96) {
  return safe(v).replace(/[^A-Za-z0-9._:-]/g, '').slice(0, max);
}

function payload(row) {
  try {
    return row?.payload_json ? JSON.parse(row.payload_json) : {};
  } catch {
    return {};
  }
}

function valueOf(x) {
  if (x == null) return null;
  if (typeof x !== 'object') return x;
  if ('textValue' in x) return x.textValue;
  if ('utf8Value' in x) return x.utf8Value;
  if ('uint64Value' in x) return Number(x.uint64Value);
  if ('int64Value' in x) return Number(x.int64Value);
  if ('boolValue' in x) return !!x.boolValue;
  if ('bytesValue' in x) return Buffer.from(x.bytesValue, 'base64').toString('utf8');
  if ('optionalValue' in x) return valueOf(x.optionalValue);
  if ('value' in x) return valueOf(x.value);
  return null;
}

function rowsOf(res) {
  const rs = res?.resultSets?.[0] || res?.resultSet || null;
  const rows = rs?.rows || [];
  const cols = (rs?.columns || []).map(c => safe(c.name || c));
  return rows.map(r => {
    const items = r.items || r;
    if (!Array.isArray(items)) return r;
    const out = {};
    items.forEach((it, i) => {
      out[cols[i] || `c${i}`] = valueOf(it);
    });
    return out;
  });
}

async function getYdb() {
  if (driverPromise) return driverPromise;

  driverPromise = (async () => {
    const { Driver, getCredentialsFromEnv } = ydbMod;
    if (!CFG.endpoint || !CFG.database) throw new Error('ydb_env_missing');

    const driver = new Driver({
      endpoint: CFG.endpoint,
      database: CFG.database,
      authService: getCredentialsFromEnv()
    });

    const ready = await driver.ready(10000);
    if (!ready) throw new Error('ydb_not_ready');

    return driver;
  })();

  return driverPromise;
}

function tvUtf8(v) {
  return ydbMod.TypedValues.utf8(String(v == null ? '' : v));
}

function tvUint64(v) {
  return ydbMod.TypedValues.uint64(num(v, 0));
}

async function query(sql, params = {}) {
  const driver = await getYdb();
  return driver.tableClient.withSession(async session => session.executeQuery(sql, params));
}

function schemaDdl() {
  return `CREATE TABLE \`${TABLE}\` (
  \`pk\` Utf8 NOT NULL,
  \`type\` Utf8,
  \`owner\` Utf8,
  \`updated_at\` Uint64,
  \`expires_at\` Uint64,
  \`payload_json\` Utf8,
  PRIMARY KEY (\`pk\`)
);`;
}

async function initSchema() {
  try {
    await query(`
      SELECT pk
      FROM ${TABLE}
      LIMIT 1;
    `);

    return {
      ok: true,
      created: false,
      table: TABLE,
      note: 'table_ready'
    };
  } catch (e) {
    return {
      ok: false,
      error: 'table_missing_or_no_access',
      table: TABLE,
      ddl: schemaDdl(),
      details: safe(e.message || e).slice(0, 500)
    };
  }
}

async function kvGet(pk) {
  const res = await query(`
    DECLARE $pk AS Utf8;
    SELECT pk, type, owner, updated_at, expires_at, payload_json
    FROM ${TABLE}
    WHERE pk = $pk;
  `, { '$pk': tvUtf8(pk) });

  const row = rowsOf(res)[0] || null;
  if (!row) return null;
  if (num(row.expires_at) > 0 && num(row.expires_at) < now()) return null;
  return row;
}

async function kvPut({ pk, type = '', owner = '', expiresAt = 0, data = {} }) {
  await query(`
    DECLARE $pk AS Utf8;
    DECLARE $type AS Utf8;
    DECLARE $owner AS Utf8;
    DECLARE $updated_at AS Uint64;
    DECLARE $expires_at AS Uint64;
    DECLARE $payload_json AS Utf8;

    UPSERT INTO ${TABLE} (pk, type, owner, updated_at, expires_at, payload_json)
    VALUES ($pk, $type, $owner, $updated_at, $expires_at, $payload_json);
  `, {
    '$pk': tvUtf8(pk),
    '$type': tvUtf8(type),
    '$owner': tvUtf8(owner),
    '$updated_at': tvUint64(now()),
    '$expires_at': tvUint64(expiresAt),
    '$payload_json': tvUtf8(JSON.stringify(data || {}))
  });
  return true;
}

async function kvDelete(pk) {
  await query(`
    DECLARE $pk AS Utf8;
    DELETE FROM ${TABLE}
    WHERE pk = $pk;
  `, { '$pk': tvUtf8(pk) });
  return true;
}

async function kvPrefix(prefix, limit = 100) {
  const to = `${prefix}\uffff`;
  const res = await query(`
    DECLARE $from AS Utf8;
    DECLARE $to AS Utf8;
    DECLARE $lim AS Uint64;

    SELECT pk, type, owner, updated_at, expires_at, payload_json
    FROM ${TABLE}
    WHERE pk >= $from AND pk < $to
    LIMIT $lim;
  `, {
    '$from': tvUtf8(prefix),
    '$to': tvUtf8(to),
    '$lim': tvUint64(limit)
  });

  const t = now();
  return rowsOf(res).filter(r => !num(r.expires_at) || num(r.expires_at) >= t);
}

async function requirePlayer(body) {
  const playerId = sanitizeId(body.playerId || body.userId);
  const clientSecret = safe(body.clientSecret || body.secret || '');
  if (!playerId) throw new Error('player_id_required');

  const row = await kvGet(`player:${playerId}`);
  if (!row) {
    if (!clientSecret) throw new Error('client_secret_required');
    await kvPut({
      pk: `player:${playerId}`,
      type: 'player',
      owner: playerId,
      data: {
        playerId,
        clientSecretHash: hash(clientSecret),
        displayName: safe(body.displayName || 'Игрок').slice(0, 80),
        avatarUrl: safe(body.avatarUrl || ''),
        createdAt: now(),
        updatedAt: now()
      }
    });
    return { playerId };
  }

  const p = payload(row);
  if (p.clientSecretHash && hash(clientSecret) !== p.clientSecretHash) throw new Error('bad_player_secret');
  return { playerId };
}

async function actionPlayerRegister(event, body) {
  const playerId = sanitizeId(body.playerId || body.userId);
  const clientSecret = safe(body.clientSecret || body.secret || '');
  if (!playerId || !clientSecret) throw new Error('player_id_and_secret_required');

  const old = payload(await kvGet(`player:${playerId}`));
  await kvPut({
    pk: `player:${playerId}`,
    type: 'player',
    owner: playerId,
    data: {
      ...old,
      playerId,
      clientSecretHash: old.clientSecretHash || hash(clientSecret),
      displayName: safe(body.displayName || old.displayName || 'Игрок').slice(0, 80),
      avatarUrl: safe(body.avatarUrl || old.avatarUrl || ''),
      updatedAt: now(),
      createdAt: old.createdAt || now()
    }
  });

  return { ok: true, playerId };
}

async function actionHeartbeat(event, body) {
  const { playerId } = await requirePlayer(body);
  const deviceId = sanitizeId(body.deviceId || 'web', 80) || 'web';
  const currentGameId = sanitizeId(body.gameId || body.currentGameId || '', 80);
  const currentRoomId = sanitizeId(body.roomId || body.currentRoomId || '', 96);
  const until = now() + CFG.presenceTtlMs;

  await kvPut({
    pk: `presence:${playerId}:${deviceId}`,
    type: 'presence',
    owner: playerId,
    expiresAt: until,
    data: {
      playerId,
      deviceId,
      currentGameId,
      currentRoomId,
      onlineUntil: until,
      publicIpHash: publicIpHash(event),
      updatedAt: now()
    }
  });

  return { ok: true, onlineUntil: until };
}

async function actionFriendStatus(event, body) {
  await requirePlayer(body);
  const targetId = sanitizeId(body.targetId || body.friendId);
  if (!targetId) throw new Error('target_required');

  const rows = await kvPrefix(`presence:${targetId}:`, 20);
  const best = rows.map(payload).sort((a, b) => num(b.onlineUntil) - num(a.onlineUntil))[0] || null;

  return {
    ok: true,
    online: !!best && num(best.onlineUntil) > now(),
    lastSeenAt: num(best?.updatedAt),
    currentGameId: safe(best?.currentGameId || ''),
    currentRoomId: safe(best?.currentRoomId || '')
  };
}

async function actionFriendInviteCreate(event, body) {
  const { playerId } = await requirePlayer(body);
  const inviteId = rid('fi');
  const secret = crypto.randomBytes(16).toString('hex');
  const expiresAt = now() + CFG.friendInviteTtlMs;

  await kvPut({
    pk: `friendInvite:${inviteId}`,
    type: 'friendInvite',
    owner: playerId,
    expiresAt,
    data: {
      inviteId,
      secretHash: hash(secret),
      fromPlayerId: playerId,
      fromProfile: {
        displayName: safe(body.displayName || 'Игрок').slice(0, 80),
        avatarUrl: safe(body.avatarUrl || '')
      },
      status: 'pending',
      createdAt: now(),
      expiresAt
    }
  });

  return { ok: true, inviteId, secret, expiresAt };
}

async function actionFriendInviteGet(event, body) {
  const inviteId = sanitizeId(body.inviteId);
  const secret = safe(body.secret || body.key || '');
  const row = inviteId ? await kvGet(`friendInvite:${inviteId}`) : null;
  const inv = payload(row);

  if (!row || inv.secretHash !== hash(secret)) return { ok: false, reason: 'invite_not_found' };
  return { ok: true, invite: { inviteId, fromPlayerId: inv.fromPlayerId, fromProfile: inv.fromProfile, status: inv.status, expiresAt: inv.expiresAt } };
}

async function actionFriendInviteAccept(event, body) {
  const { playerId } = await requirePlayer(body);
  const inviteId = sanitizeId(body.inviteId);
  const secret = safe(body.secret || body.key || '');
  const row = inviteId ? await kvGet(`friendInvite:${inviteId}`) : null;
  const inv = payload(row);

  if (!row || inv.secretHash !== hash(secret)) return { ok: false, reason: 'invite_not_found' };
  if (inv.fromPlayerId === playerId) return { ok: false, reason: 'self_friend_forbidden' };

  const at = now();
  const myProfile = { friendId: playerId, displayName: safe(body.displayName || 'Слушатель').slice(0, 80), avatarUrl: safe(body.avatarUrl || '').slice(0, 400), updatedAt: at };

  await kvPut({ pk: `friend:${playerId}:${inv.fromPlayerId}`, type: 'friend', owner: playerId, data: { ownerPlayerId: playerId, friendPlayerId: inv.fromPlayerId, createdAt: at, status: 'active', profile: inv.fromProfile || {} } });
  await kvPut({ pk: `friend:${inv.fromPlayerId}:${playerId}`, type: 'friend', owner: inv.fromPlayerId, data: { ownerPlayerId: inv.fromPlayerId, friendPlayerId: playerId, createdAt: at, status: 'active', profile: { displayName: myProfile.displayName, avatarUrl: myProfile.avatarUrl } } });
  await kvPut({ pk: `friendInvite:${inviteId}`, type: 'friendInvite', owner: inv.fromPlayerId, expiresAt: inv.expiresAt, data: { ...inv, status: 'accepted', acceptedByPlayerId: playerId, acceptedAt: at } });

  // сохраняем публичный профиль обоих, чтобы friend_list всегда показывал имя/аватар
  await kvPut({ pk: `profile:${playerId}`, type: 'profile', owner: playerId, data: myProfile }).catch(() => null);
  if (inv.fromProfile) await kvPut({ pk: `profile:${inv.fromPlayerId}`, type: 'profile', owner: inv.fromPlayerId, data: { friendId: inv.fromPlayerId, displayName: safe(inv.fromProfile.displayName || 'Друг').slice(0, 80), avatarUrl: safe(inv.fromProfile.avatarUrl || '').slice(0, 400), updatedAt: at } }).catch(() => null);

  return { ok: true, friendPlayerId: inv.fromPlayerId };
}

async function actionRoomCreate(event, body) {
  const { playerId } = await requirePlayer(body);
  const gameId = sanitizeId(body.gameId || 'game', 80);
  const roomId = rid('room');
  const roomSecret = crypto.randomBytes(16).toString('hex');
  const hostPeerId = sanitizeId(body.peerId || `${playerId}:host:${rid('p')}`, 120);
  const guestPeerId = `${roomId}:guest`;
  const expiresAt = now() + CFG.roomTtlMs;

  const room = {
    roomId,
    gameId,
    status: 'waiting',
    hostPlayerId: playerId,
    guestPlayerId: '',
    hostPeerId,
    guestPeerId,
    roomSecretHash: hash(roomSecret),
    createdAt: now(),
    updatedAt: now(),
    reconnectUntil: expiresAt
  };

  await kvPut({ pk: `room:${roomId}`, type: 'room', owner: playerId, expiresAt, data: room });

  return { ok: true, roomId, roomSecret, hostPeerId, guestPeerId, room };
}

async function actionRoomJoin(event, body) {
  const { playerId } = await requirePlayer(body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);

  if (!row || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };

  if (room.guestPlayerId && room.guestPlayerId !== playerId) {
    return { ok: false, reason: 'room_already_has_guest' };
  }

  const requestedPeerId = sanitizeId(body.peerId || '', 120);
  room.guestPlayerId = playerId;
  room.guestPeerId = requestedPeerId || sanitizeId(room.guestPeerId || `${roomId}:guest`, 120) || `${roomId}:guest`;
  room.status = room.status === 'waiting' ? 'accepted' : room.status;
  room.updatedAt = now();

  await kvPut({ pk: `room:${roomId}`, type: 'room', owner: room.hostPlayerId, expiresAt: room.reconnectUntil, data: room });

  return {
    ok: true,
    roomId,
    roomSecret,
    hostPeerId: room.hostPeerId,
    guestPeerId: room.guestPeerId,
    ranked: !!room.ranked,
    localOnly: !!room.localOnly,
    matchMode: safe(room.matchMode || (room.ranked ? 'ranked' : 'casual')),
    room
  };
}

async function actionRoomGet(event, body) {
  await requirePlayer(body);
  const roomId = sanitizeId(body.roomId);
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);
  if (!row) return { ok: false, reason: 'room_not_found' };
  return { ok: true, room };
}

async function actionRoomClose(event, body) {
  await requirePlayer(body);
  const roomId = sanitizeId(body.roomId);
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);
  if (!row) return { ok: true, closed: false };
  room.status = 'closed';
  room.closedAt = now();
  room.updatedAt = now();
  await kvPut({ pk: `room:${roomId}`, type: 'room', owner: room.hostPlayerId || '', expiresAt: now() + 600000, data: room });
  return { ok: true, closed: true };
}

async function actionSignalSend(event, body) {
  const { playerId } = await requirePlayer(body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const fromPeerId = sanitizeId(body.fromPeerId || body.peerId, 140);
  const toPeerId = sanitizeId(body.toPeerId || body.targetPeerId, 140);
  const type = sanitizeId(body.type || body.signalType || body.payload?.type, 40);
  const payloadData = body.payload?.data !== undefined ? body.payload.data : body.payload;

  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);
  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };
  if (!toPeerId || !fromPeerId || !type) throw new Error('bad_signal');

  const seq = `${now().toString().padStart(13, '0')}_${crypto.randomBytes(4).toString('hex')}`;
  const expiresAt = now() + CFG.signalTtlMs;

  await kvPut({
    pk: `signal:${roomId}:${toPeerId}:${seq}`,
    type: 'signal',
    owner: toPeerId,
    expiresAt,
    data: {
      roomId,
      fromPlayerId: playerId,
      fromPeerId,
      toPeerId,
      type,
      data: payloadData,
      createdAt: now(),
      expiresAt
    }
  });

  return { ok: true, seq };
}

async function actionSignalPoll(event, body) {
  await requirePlayer(body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const peerId = sanitizeId(body.peerId, 140);

  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);
  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };
  if (!peerId) throw new Error('peer_id_required');

  const rows = await kvPrefix(`signal:${roomId}:${peerId}:`, 200);
  const messages = rows.map(payload).sort((a, b) => num(a.createdAt) - num(b.createdAt));

  await Promise.all(rows.map(r => kvDelete(r.pk).catch(() => null)));

  return { ok: true, messages };
}

async function actionGameInviteCreate(event, body) {
  const { playerId } = await requirePlayer(body);
  const toPlayerId = sanitizeId(body.toPlayerId || body.friendId);
  const gameId = sanitizeId(body.gameId || 'game', 80);
  if (!toPlayerId) throw new Error('to_player_required');

  const gameInviteId = rid('gi');
  const expiresAt = now() + CFG.gameInviteTtlMs;

  await kvPut({
    pk: `gameInvite:${gameInviteId}`,
    type: 'gameInvite',
    owner: toPlayerId,
    expiresAt,
    data: {
      gameInviteId,
      gameId,
      fromPlayerId: playerId,
      toPlayerId,
      status: 'pending',
      createdAt: now(),
      updatedAt: now(),
      expiresAt
    }
  });

  return { ok: true, gameInviteId, expiresAt };
}

async function actionGameInvitePoll(event, body) {
  const { playerId } = await requirePlayer(body);
  const rows = await kvPrefix('gameInvite:', 200);
  const items = rows.map(payload).filter(x => x.toPlayerId === playerId || x.fromPlayerId === playerId);
  return { ok: true, items };
}

async function actionGameInviteSet(event, body, status) {
  const { playerId } = await requirePlayer(body);
  const gameInviteId = sanitizeId(body.gameInviteId || body.inviteId);
  const row = gameInviteId ? await kvGet(`gameInvite:${gameInviteId}`) : null;
  const inv = payload(row);
  if (!row) return { ok: false, reason: 'invite_not_found' };
  if (![inv.toPlayerId, inv.fromPlayerId].includes(playerId)) throw new Error('invite_forbidden');

  inv.status = status;
  inv.updatedAt = now();
  if (status === 'accepted') inv.acceptedAt = now();
  if (status === 'rejected') inv.rejectedAt = now();

  await kvPut({ pk: `gameInvite:${gameInviteId}`, type: 'gameInvite', owner: inv.toPlayerId, expiresAt: inv.expiresAt, data: inv });
  return { ok: true, invite: inv };
}

// ===== FRIENDS MODULE (Phase A) =====

async function actionProfileSet(event, body) {
  const { playerId } = await requirePlayer(body);

  const profile = {
    friendId: playerId,
    displayName: safe(body.displayName || 'Слушатель').slice(0, 80),
    avatarUrl: safe(body.avatarUrl || '').slice(0, 400),
    updatedAt: now()
  };

  await kvPut({
    pk: `profile:${playerId}`,
    type: 'profile',
    owner: playerId,
    data: profile
  });

  return { ok: true, profile };
}

async function actionProfileGet(event, body) {
  await requirePlayer(body);

  const targetId = sanitizeId(body.targetId || body.friendId);
  if (!targetId) return { ok: true, profile: null };

  const row = await kvGet(`profile:${targetId}`);
  const data = payload(row);
  return { ok: true, profile: data && data.friendId ? data : null };
}

async function actionFriendList(event, body) {
  const { playerId } = await requirePlayer(body);

  const rows = await kvPrefix(`friend:${playerId}:`, 300);
  const items = [];

  for (const row of rows) {
    const data = payload(row);
    if (!data) continue;
    if (data.status && data.status !== 'active') continue;

    const friendId = sanitizeId(data.friendPlayerId || data.friendId);
    if (!friendId) continue;

    let profile = data.profile || null;
    if (!profile || !profile.displayName) {
      const pr = payload(await kvGet(`profile:${friendId}`));
      if (pr && pr.friendId) profile = pr;
    }

    items.push({
      friendId,
      profile: profile || { friendId, displayName: 'Друг', avatarUrl: '' },
      createdAt: num(data.createdAt)
    });
  }

  items.sort((a, b) => num(b.createdAt) - num(a.createdAt));
  return { ok: true, items };
}

async function actionFriendRemove(event, body) {
  const { playerId } = await requirePlayer(body);

  const targetId = sanitizeId(body.targetId || body.friendId);
  if (!targetId) throw new Error('target_required');

  await kvDelete(`friend:${playerId}:${targetId}`).catch(() => null);
  await kvDelete(`friend:${targetId}:${playerId}`).catch(() => null);

  return { ok: true, removed: true };
}

async function actionPresenceBatch(event, body) {
  await requirePlayer(body);

  const ids = Array.isArray(body.friendIds)
    ? body.friendIds.map(sanitizeId).filter(Boolean).slice(0, 50)
    : [];

  const presence = {};
  const t = now();

  for (const id of ids) {
    const rows = await kvPrefix(`presence:${id}:`, 10);
    const online = rows.some(r => {
      const data = payload(r);
      return num(data.onlineUntil) > t;
    });
    presence[id] = { online };
  }

  return { ok: true, presence };
}

async function sendSystemWebPush({ toPlayerId, title, body, url = './', tag = 'vi3-notification', requireInteraction = false } = {}) {
  if (!CFG.webPushFunctionUrl || !CFG.webPushSecret || !toPlayerId) return { ok: false, skipped: true };

  try {
    const res = await fetch(CFG.webPushFunctionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vi3-Admin': CFG.webPushSecret
      },
      body: JSON.stringify({
        action: 'send_to_player',
        adminSecret: CFG.webPushSecret,
        playerId: toPlayerId,
        title,
        body,
        url,
        tag,
        requireInteraction
      })
    });

    const json = await res.json().catch(() => ({}));
    return json;
  } catch (err) {
    return { ok: false, error: safe(err.message || err) };
  }
}

async function actionPushSend(event, body) {
  const { playerId } = await requirePlayer(body);

  const toFriendId = sanitizeId(body.toFriendId || body.toPlayerId);
  if (!toFriendId) throw new Error('to_friend_required');

  const pushId = rid('push');
  const expiresAt = now() + 7 * 24 * 60 * 60 * 1000;

  const kind = safe(body.kind || 'GENERIC').slice(0, 40);
  const gameId = sanitizeId(body.gameId || '');
  const roomId = sanitizeId(body.roomId || '');
  const roomSecret = safe(body.roomSecret || '');
  const text = safe(body.text || '').slice(0, 300);
  const createdAt = now();

  await kvPut({
    pk: `push:${toFriendId}:${createdAt.toString().padStart(13, '0')}_${pushId}`,
    type: 'push',
    owner: toFriendId,
    expiresAt,
    data: {
      pushId,
      fromFriendId: playerId,
      kind,
      gameId,
      roomId,
      roomSecret,
      text,
      createdAt,
      expiresAt
    }
  });

  const profile = payload(await kvGet(`profile:${playerId}`));
  const fromName = safe(profile.displayName || body.displayName || 'Друг').slice(0, 80);

  const webPush = await sendSystemWebPush({
    toPlayerId: toFriendId,
    title: kind === 'GAME_INVITE' ? '🎮 Вызов на дуэль' : '🔔 Витрина Разбита',
    body: kind === 'GAME_INVITE' ? `${fromName} приглашает в Войну Сердец` : (text || `${fromName} отправил уведомление`),
    url: kind === 'GAME_INVITE' && gameId && roomId && roomSecret
      ? `./?gcGame=${encodeURIComponent(gameId)}&room=${encodeURIComponent(roomId)}&key=${encodeURIComponent(roomSecret)}`
      : './',
    tag: kind === 'GAME_INVITE' ? `game-${roomId || pushId}` : `push-${pushId}`,
    requireInteraction: kind === 'GAME_INVITE'
  });

  return { ok: true, pushId, webPush };
}

async function actionPushPoll(event, body) {
  const { playerId } = await requirePlayer(body);

  const rows = await kvPrefix(`push:${playerId}:`, 100);
  const items = rows.map(payload).sort((a, b) => num(a.createdAt) - num(b.createdAt));

  await Promise.all(rows.map(r => kvDelete(r.pk).catch(() => null)));

  return { ok: true, items };
}

function chatRoomId(a, b) {
  return [sanitizeId(a), sanitizeId(b)].sort().join(':');
}

async function actionChatSend(event, body) {
  const { playerId } = await requirePlayer(body);
  const toFriendId = sanitizeId(body.toFriendId || body.friendId);
  const text = safe(body.text || '').slice(0, 500);
  if (!toFriendId) throw new Error('to_friend_required');
  if (!text) throw new Error('text_required');

  const createdAt = now();
  const msgId = rid('chat');
  const room = chatRoomId(playerId, toFriendId);

  const msg = {
    msgId,
    room,
    fromFriendId: playerId,
    toFriendId,
    text,
    createdAt
  };

  await kvPut({
    pk: `chat:${room}:${createdAt.toString().padStart(13, '0')}:${msgId}`,
    type: 'chat',
    owner: room,
    expiresAt: createdAt + 30 * 24 * 60 * 60 * 1000,
    data: msg
  });

  const chatPushId = rid('push');

  await kvPut({
    pk: `push:${toFriendId}:${createdAt.toString().padStart(13, '0')}_${chatPushId}`,
    type: 'push',
    owner: toFriendId,
    expiresAt: createdAt + 7 * 24 * 60 * 60 * 1000,
    data: {
      pushId: chatPushId,
      fromFriendId: playerId,
      kind: 'CHAT_MESSAGE',
      text,
      createdAt,
      expiresAt: createdAt + 7 * 24 * 60 * 60 * 1000
    }
  }).catch(() => null);

  const profile = payload(await kvGet(`profile:${playerId}`));
  const fromName = safe(profile.displayName || body.displayName || 'Друг').slice(0, 80);

  const webPush = await sendSystemWebPush({
    toPlayerId: toFriendId,
    title: `💬 ${fromName}`,
    body: text,
    url: './?openFriends=1',
    tag: `chat-${chatRoomId(playerId, toFriendId)}`,
    requireInteraction: false
  });

  return { ok: true, msgId, createdAt, webPush };
}

async function actionChatPoll(event, body) {
  const { playerId } = await requirePlayer(body);
  const friendId = sanitizeId(body.friendId || body.withFriendId);
  const after = num(body.after, 0);
  if (!friendId) throw new Error('friend_required');

  const room = chatRoomId(playerId, friendId);
  const rows = await kvPrefix(`chat:${room}:`, 120);
  const items = rows
    .map(payload)
    .filter(x => num(x.createdAt) > after)
    .sort((a, b) => num(a.createdAt) - num(b.createdAt))
    .slice(-80);

  return { ok: true, items };
}

async function actionMatchSubmit(event, body) {
  const { playerId } = await requirePlayer(body);
  const matchId = sanitizeId(body.matchId || rid('match'));
  const roomId = sanitizeId(body.roomId || '');
  const expiresAt = 0;

  let rankedAllowed = false;
  let room = null;

  if (roomId) {
    const roomRow = await kvGet(`room:${roomId}`);
    room = payload(roomRow);
    rankedAllowed = !!roomRow
      && !!room.ranked
      && [room.hostPlayerId, room.guestPlayerId].includes(playerId);
  }

  const requestedRanked = body.ranked === true || body.result?.ranked === true;
  const ranked = requestedRanked && rankedAllowed;

  const data = {
    matchId,
    gameId: sanitizeId(body.gameId || ''),
    roomId,
    playerId,
    ranked,
    localOnly: !!room?.localOnly,
    matchMode: ranked ? 'ranked' : 'casual',
    result: body.result || {},
    resultHash: safe(body.resultHash || ''),
    transcriptHash: safe(body.transcriptHash || ''),
    createdAt: now()
  };

  await kvPut({ pk: `match:${matchId}:${playerId}`, type: 'match', owner: playerId, expiresAt, data });

  if (!ranked) {
    return {
      ok: true,
      matchId,
      ranked: false,
      rated: false,
      reason: rankedAllowed ? 'casual_match_not_rated' : 'room_not_ranked_or_forbidden'
    };
  }

  const pRow = await kvGet(`profile:${playerId}`);
  const pData = payload(pRow) || {
    friendId: playerId,
    displayName: safe(body.displayName || 'Игрок').slice(0, 80),
    avatarUrl: ''
  };

  const isWin = body.result?.status === 'win';
  pData.rating = Math.max(100, (pData.rating || 1000) + (isWin ? 25 : -15));
  pData.wins = (pData.wins || 0) + (isWin ? 1 : 0);
  pData.matches = (pData.matches || 0) + 1;
  pData.updatedAt = now();

  await kvPut({ pk: `profile:${playerId}`, type: 'profile', owner: playerId, data: pData });

  return { ok: true, matchId, ranked: true, rated: true };
}

async function actionLeaderboardGet(event, body) {
  const rows = await kvPrefix('profile:', 1000);
  const leaders = rows.map(payload)
    .filter(p => p.matches > 0)
    .sort((a, b) => (b.rating || 1000) - (a.rating || 1000))
    .slice(0, 50)
    .map(p => ({
       playerId: p.friendId,
       displayName: p.displayName,
       avatarUrl: p.avatarUrl,
       rating: p.rating || 1000,
       wins: p.wins || 0,
       matches: p.matches || 0
    }));
  return { ok: true, leaders };
}

async function actionRtcConfig(event, body) {
  const iceServers = [
    { urls: 'stun:stun.sipnet.ru:3478' },
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' }
  ];

  const hasTurn = !CFG.turnDisabled && !!(CFG.turnUrls.length && CFG.turnUsername && CFG.turnCredential);

  if (hasTurn) {
    iceServers.unshift({
      urls: CFG.turnUrls,
      username: CFG.turnUsername,
      credential: CFG.turnCredential
    });
  }

  return {
    ok: true,
    iceServers,
    hasTurn,
    turnDisabled: CFG.turnDisabled
  };
}

async function actionWebPushConfig(event, body) {
  return {
    ok: true,
    vapidPublicKey: CFG.vapidPublicKey,
    enabled: !!CFG.vapidPublicKey
  };
}

async function actionWebPushSubscribe(event, body) {
  const { playerId } = await requirePlayer(body);
  const sub = body.subscription || {};
  const endpoint = safe(sub.endpoint || '');
  if (!endpoint) throw new Error('push_endpoint_required');

  const endpointHash = hash(endpoint).slice(0, 32);
  await kvPut({
    pk: `webPushSub:${playerId}:${endpointHash}`,
    type: 'webPushSub',
    owner: playerId,
    expiresAt: 0,
    data: {
      playerId,
      endpointHash,
      subscription: sub,
      userAgent: safe(body.userAgent || '').slice(0, 220),
      createdAt: now(),
      updatedAt: now()
    }
  });

  return { ok: true, endpointHash };
}

async function actionWebPushUnsubscribe(event, body) {
  const { playerId } = await requirePlayer(body);
  const endpoint = safe(body.endpoint || body.subscription?.endpoint || '');
  if (!endpoint) return { ok: true, removed: false };

  await kvDelete(`webPushSub:${playerId}:${hash(endpoint).slice(0, 32)}`).catch(() => null);
  return { ok: true, removed: true };
}

function nearbyCode() {
  return String(crypto.randomInt(100000, 999999));
}

async function actionNearbyFriendCreate(event, body) {
  const { playerId } = await requirePlayer(body);
  const inv = await actionFriendInviteCreate(event, body);
  const code = nearbyCode();
  const expiresAt = now() + CFG.nearbyTtlMs;

  await kvPut({
    pk: `nearbyFriend:${code}`,
    type: 'nearbyFriend',
    owner: playerId,
    expiresAt,
    data: {
      code,
      fromPlayerId: playerId,
      inviteId: inv.inviteId,
      secret: inv.secret,
      createdAt: now(),
      expiresAt
    }
  });

  return { ok: true, code, inviteId: inv.inviteId, secret: inv.secret, expiresAt };
}

async function actionNearbyFriendJoin(event, body) {
  await requirePlayer(body);
  const code = safe(body.code || '').replace(/\D/g, '').slice(0, 6);
  if (!code) throw new Error('nearby_code_required');

  const row = await kvGet(`nearbyFriend:${code}`);
  const data = payload(row);
  if (!row || !data.inviteId || !data.secret) return { ok: false, reason: 'nearby_code_not_found' };

  return actionFriendInviteAccept(event, {
    ...body,
    inviteId: data.inviteId,
    secret: data.secret
  });
}

async function actionNearbyGameCreate(event, body) {
  const { playerId } = await requirePlayer(body);
  const gameId = sanitizeId(body.gameId || 'war_hearts');
  let roomId = sanitizeId(body.roomId || '');
  let roomSecret = safe(body.roomSecret || body.secret || body.key || '');

  if (roomId && roomSecret) {
    const row = await kvGet(`room:${roomId}`);
    const room = payload(row);
    if (!row || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };
    if (room.hostPlayerId !== playerId) return { ok: false, reason: 'room_owner_forbidden' };
  } else {
    const room = await actionRoomCreate(event, body);
    roomId = room.roomId;
    roomSecret = room.roomSecret;
  }

  const code = nearbyCode();
  const expiresAt = now() + CFG.nearbyTtlMs;

  await kvPut({
    pk: `nearbyGame:${code}`,
    type: 'nearbyGame',
    owner: playerId,
    expiresAt,
    data: {
      code,
      gameId,
      fromPlayerId: playerId,
      roomId,
      roomSecret,
      createdAt: now(),
      expiresAt
    }
  });

  return {
    ok: true,
    code,
    gameId,
    roomId,
    roomSecret,
    expiresAt
  };
}

async function actionNearbyGameJoin(event, body) {
  await requirePlayer(body);
  const code = safe(body.code || '').replace(/\D/g, '').slice(0, 6);
  if (!code) throw new Error('nearby_game_code_required');

  const row = await kvGet(`nearbyGame:${code}`);
  const data = payload(row);
  if (!row || !data.roomId || !data.roomSecret) return { ok: false, reason: 'nearby_game_not_found' };

  return {
    ok: true,
    gameId: sanitizeId(data.gameId || 'war_hearts'),
    roomId: data.roomId,
    roomSecret: data.roomSecret,
    expiresAt: data.expiresAt
  };
}
// ─── LAN Wi-Fi: регистрация и разрешение кодов комнат ───────────────────────
async function actionLanCodeRegister(event, body) {
  const { playerId } = await requirePlayer(body);
  const code = safe(body.code || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 6);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret);

  if (!code || code.length < 4) throw new Error('lan_code_required');
  if (!roomId || !roomSecret) throw new Error('room_data_required');

  const row = await kvGet(`room:${roomId}`);
  const room = payload(row);
  if (!row || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };
  if (room.hostPlayerId !== playerId) return { ok: false, reason: 'room_owner_forbidden' };

  room.ranked = !!body.ranked;
  room.localOnly = true;
  room.matchMode = room.ranked ? 'ranked' : 'casual';
  room.updatedAt = now();

  const ttlMs = Math.min(600000, Math.max(60000, num(body.ttlMs, 300000)));
  const expiresAt = now() + ttlMs;

  await kvPut({
    pk: `room:${roomId}`,
    type: 'room',
    owner: room.hostPlayerId || playerId,
    expiresAt: room.reconnectUntil || expiresAt,
    data: room
  });

  await kvPut({
    pk: `lanCode:${code}`,
    type: 'lanCode',
    owner: playerId,
    expiresAt,
    data: {
      code,
      roomId,
      roomSecret,
      ranked: !!body.ranked,
      hostPlayerId: playerId,
      createdAt: now(),
      expiresAt
    }
  });

  return { ok: true, code, expiresAt };
}

async function actionLanCodeResolve(event, body) {
await requirePlayer(body);
const code = safe(body.code || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 6);
if (!code) throw new Error('lan_code_required');
const row = await kvGet(`lanCode:${code}`);
const data = payload(row);
if (!row || !data.roomId || !data.roomSecret) return { ok: false, reason: 'lan_room_not_found' };
return {
  ok: true,
  code: data.code,
  roomId: data.roomId,
  roomSecret: data.roomSecret,
  ranked: !!data.ranked,
  localOnly: true,
  matchMode: data.ranked ? 'ranked' : 'casual',
  hostPlayerId: data.hostPlayerId,
  expiresAt: data.expiresAt
};
}
const ACTIONS = {
  player_register: actionPlayerRegister,
  presence_heartbeat: actionHeartbeat,
  heartbeat: actionHeartbeat,
  friend_status_check: actionFriendStatus,
  check_status: actionFriendStatus,
  friend_invite_create: actionFriendInviteCreate,
  friend_invite_get: actionFriendInviteGet,
  friend_invite_accept: actionFriendInviteAccept,
  room_create: actionRoomCreate,
  room_join: actionRoomJoin,
  room_get: actionRoomGet,
  room_close: actionRoomClose,
  room_delete: actionRoomClose,
  signal_send: actionSignalSend,
  signal_poll: actionSignalPoll,
  send_signal: actionSignalSend,
  poll_signals: actionSignalPoll,
  game_invite_create: actionGameInviteCreate,
  game_invite_poll: actionGameInvitePoll,
  game_invite_accept: (e, b) => actionGameInviteSet(e, b, 'accepted'),
  game_invite_reject: (e, b) => actionGameInviteSet(e, b, 'rejected'),
  game_invite_cancel: (e, b) => actionGameInviteSet(e, b, 'cancelled'),
  match_submit_result: actionMatchSubmit,
  leaderboard_get: actionLeaderboardGet,
  rtc_config: actionRtcConfig,
  webpush_config: actionWebPushConfig,
  webpush_subscribe: actionWebPushSubscribe,
  webpush_unsubscribe: actionWebPushUnsubscribe,
  nearby_friend_create: actionNearbyFriendCreate,
  nearby_friend_join: actionNearbyFriendJoin,
  nearby_game_create: actionNearbyGameCreate,
  nearby_game_join: actionNearbyGameJoin,
  lan_code_register: actionLanCodeRegister,
  lan_code_resolve: actionLanCodeResolve,

  // ===== FRIENDS MODULE (Phase A) =====
  profile_set: actionProfileSet,
  profile_get: actionProfileGet,
  friend_list: actionFriendList,
  friend_remove: actionFriendRemove,
  presence_batch: actionPresenceBatch,
  push_send: actionPushSend,
  push_poll: actionPushPoll,
  chat_send: actionChatSend,
  chat_poll: actionChatPoll
};

exports.handler = async event => {
  const method = safe(event.httpMethod || event.requestContext?.http?.method || event.requestContext?.httpMethod || '').toUpperCase();
  if (method === 'OPTIONS') return { statusCode: 200, headers: corsHeaders(event), body: '' };

  const body = parseBody(event);
  const action = safe(body.action || body.mode || event.queryStringParameters?.action || event.queryStringParameters?.mode || 'ping');

  try {
    if (action === 'ping') {
      return reply(event, 200, {
        ok: true,
        service: 'vi3-signaling',
        ydbConfigured: !!(CFG.endpoint && CFG.database),
        table: TABLE,
        actions: Object.keys(ACTIONS).length,
        turnDisabled: CFG.turnDisabled,
        webPushConfigured: !!(CFG.webPushFunctionUrl && CFG.webPushSecret),
        vapidPublicConfigured: !!CFG.vapidPublicKey,
        ts: now()
      });
    }

    if (action === 'init_schema') {
      if (!CFG.adminSecret || safe(body.adminSecret) !== CFG.adminSecret) return reply(event, 403, { ok: false, error: 'bad_admin_secret' });
      return reply(event, 200, await initSchema());
    }

    const fn = ACTIONS[action];
    if (!fn) return reply(event, 400, { ok: false, error: 'bad_action', allowed: Object.keys(ACTIONS).concat(['ping', 'init_schema']) });

    return reply(event, 200, await fn(event, body));
  } catch (e) {
    const msg = safe(e.message || 'server_error');
    const status = /required|bad_|forbidden|not_found/.test(msg) ? 400 : 500;
    return reply(event, status, { ok: false, error: msg });
  }
};
