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
  webPushSecret: safe(process.env.WEBPUSH_SECRET || ''),
  socialSessionSecret: safe(process.env.SOCIAL_SESSION_SECRET || ''),
  socialSessionTtlMs: Math.max(
    300000,
    Math.min(
      num(process.env.SOCIAL_SESSION_TTL_MS, 1200000),
      3600000
    )
  ),
  chatE2eeV2: safe(process.env.CHAT_E2EE_V2 || '0') === '1',
  turnSharedSecret: safe(process.env.TURN_SHARED_SECRET || ''),
  turnCredentialTtlSec: Math.max(
    300,
    Math.min(num(process.env.TURN_CREDENTIAL_TTL_SEC, 3600), 86400)
  )
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

function base64url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64urlDecode(value) {
  const raw = safe(value).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(raw + '='.repeat((4 - raw.length % 4) % 4), 'base64');
}

function hmac(value) {
  if (!CFG.socialSessionSecret) throw new Error('social_session_not_configured');
  return base64url(
    crypto.createHmac('sha256', CFG.socialSessionSecret)
      .update(String(value || ''), 'utf8')
      .digest()
  );
}

function timingSafeEqualText(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function makeFriendId(yandexId) {
  return `ya_${hash(`friend:${safe(yandexId)}`).slice(0, 24)}`;
}

function issueSocialSession(claims = {}) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'VI3S' }));
  const body = base64url(JSON.stringify(claims));
  const unsigned = `${header}.${body}`;
  return `${unsigned}.${hmac(unsigned)}`;
}

function verifySocialSession(token) {
  const parts = safe(token).split('.');
  if (parts.length !== 3) throw new Error('bad_social_session');

  const unsigned = `${parts[0]}.${parts[1]}`;
  if (!timingSafeEqualText(hmac(unsigned), parts[2])) {
    throw new Error('bad_social_session');
  }

  let claims;
  try {
    claims = JSON.parse(base64urlDecode(parts[1]).toString('utf8'));
  } catch {
    throw new Error('bad_social_session');
  }

  if (!claims?.sub || !claims?.yidHash) throw new Error('bad_social_session');
  if (num(claims.exp) <= now()) throw new Error('social_session_expired');
  if (num(claims.iat) > now() + 60000) throw new Error('bad_social_session_clock');

  return claims;
}

function headerValue(event, name) {
  const headers = event?.headers || {};
  const target = String(name || '').toLowerCase();
  const key = Object.keys(headers).find(x => String(x).toLowerCase() === target);
  return key ? safe(headers[key]) : '';
}

async function verifyYandexOAuth(event, body) {
  const token = headerValue(event, 'x-yandex-oauth');
  if (!token) throw new Error('yandex_oauth_required');

  const response = await fetch('https://login.yandex.ru/info?format=json', {
    method: 'GET',
    headers: {
      Authorization: `OAuth ${token}`,
      Accept: 'application/json'
    }
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error('bad_yandex_oauth');
    }
    throw new Error('yandex_oauth_unavailable');
  }

  const profile = await response.json().catch(() => null);
  const yandexId = safe(profile?.id);
  if (!yandexId) throw new Error('bad_yandex_profile');

  return {
    yandexId,
    friendId: makeFriendId(yandexId),
    displayName: safe(
      body.displayName ||
      profile.real_name ||
      profile.display_name ||
      profile.login ||
      'Слушатель'
    ).slice(0, 80),
    avatarUrl: safe(body.avatarUrl || '').slice(0, 400)
  };
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
    'Access-Control-Allow-Headers': reqHeaders || 'Content-Type, Accept, X-Requested-With, X-Vi3-Session, X-Yandex-OAuth, X-Vi3-Admin',
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
  })().catch(err => {
    driverPromise = null;
    throw err;
  });

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

async function kvCompareAndPut({
  row,
  type = '',
  owner = '',
  expiresAt = 0,
  data = {}
}) {
  if (!row?.pk) throw new Error('cas_row_required');

  const expectedUpdatedAt = num(row.updated_at);
  const nextUpdatedAt = Math.max(
    now(),
    expectedUpdatedAt + 1
  );

  const result = await query(`
    DECLARE $pk AS Utf8;
    DECLARE $expected_updated_at AS Uint64;
    DECLARE $type AS Utf8;
    DECLARE $owner AS Utf8;
    DECLARE $next_updated_at AS Uint64;
    DECLARE $expires_at AS Uint64;
    DECLARE $payload_json AS Utf8;

    UPDATE ${TABLE}
    SET
      type = $type,
      owner = $owner,
      updated_at = $next_updated_at,
      expires_at = $expires_at,
      payload_json = $payload_json
    WHERE pk = $pk
      AND updated_at = $expected_updated_at
    RETURNING pk, updated_at;
  `, {
    '$pk': tvUtf8(row.pk),
    '$expected_updated_at': tvUint64(expectedUpdatedAt),
    '$type': tvUtf8(type),
    '$owner': tvUtf8(owner),
    '$next_updated_at': tvUint64(nextUpdatedAt),
    '$expires_at': tvUint64(expiresAt),
    '$payload_json': tvUtf8(JSON.stringify(data || {}))
  });

  const changed = rowsOf(result)[0] || null;

  return !!changed &&
    changed.pk === row.pk &&
    num(changed.updated_at) === nextUpdatedAt;
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

async function enforceRateLimit({
  scope,
  actor,
  limit,
  windowMs
}) {
  const cleanScope = sanitizeId(scope, 60);
  const cleanActor = safe(actor);

  if (!cleanScope || !cleanActor) {
    throw new Error('rate_limit_identity_required');
  }

  const duration = Math.max(
    1000,
    Math.min(num(windowMs), 24 * 60 * 60 * 1000)
  );
  const max = Math.max(1, Math.min(num(limit), 1000));
  const at = now();
  const bucket = Math.floor(at / duration);
  const actorHash = hash(`rate:${cleanActor}`).slice(0, 24);
  const prefix =
    `rate:${cleanScope}:${actorHash}:${bucket}:`;
  const pk = `${prefix}${rid('hit')}`;
  const expiresAt = (bucket + 1) * duration + 60000;

  await kvPut({
    pk,
    type: 'rateLimit',
    owner: actorHash,
    expiresAt,
    data: {
      scope: cleanScope,
      at
    }
  });

  const rows = await kvPrefix(prefix, max + 1);

  if (rows.length > max) {
    await kvDelete(pk).catch(() => null);

    const error = new Error('rate_limit_exceeded');
    error.httpStatus = 429;
    throw error;
  }

  return {
    ok: true,
    remaining: Math.max(0, max - rows.length),
    resetAt: (bucket + 1) * duration
  };
}

async function areFriends(a, b) {
  const aa = sanitizeId(a);
  const bb = sanitizeId(b);
  if (!aa || !bb || aa === bb) return false;

  const row = await kvGet(`friend:${aa}:${bb}`);
  const data = payload(row);
  return !!row && (!data.status || data.status === 'active');
}

async function requireFriendship(playerId, targetId) {
  const target = sanitizeId(targetId);
  if (!target) throw new Error('friend_required');
  if (!(await areFriends(playerId, target))) throw new Error('friendship_required');
  return target;
}

async function requireFriendContext(event, body, {
  friendFields = ['friendId', 'withFriendId'],
  allowSelf = false
} = {}) {
  const auth = await requirePlayer(event, body);
  const rawFriendId = friendFields
    .map(field => body?.[field])
    .find(value => safe(value));

  const friendId = sanitizeId(rawFriendId);
  if (!friendId) throw new Error('friend_required');

  if (friendId === auth.playerId) {
    if (!allowSelf) throw new Error('self_friend_forbidden');
  } else {
    await requireFriendship(auth.playerId, friendId);
  }

  return {
    ...auth,
    friendId,
    room: chatRoomId(auth.playerId, friendId)
  };
}

async function getActiveFriendIdSet(playerId, limit = 300) {
  const rows = await kvPrefix(`friend:${sanitizeId(playerId)}:`, limit);
  return new Set(
    rows
      .map(payload)
      .filter(data => data && (!data.status || data.status === 'active'))
      .map(data => sanitizeId(data.friendPlayerId || data.friendId))
      .filter(Boolean)
  );
}

function isRoomParticipant(room, playerId) {
  return [room?.hostPlayerId, room?.guestPlayerId]
    .filter(Boolean)
    .includes(playerId);
}

function expectedPeerForPlayer(room, playerId) {
  if (room?.hostPlayerId === playerId) return safe(room.hostPeerId);
  if (room?.guestPlayerId === playerId) return safe(room.guestPeerId);
  return '';
}

function isRoomViewer(room, playerId) {
  return isRoomParticipant(room, playerId) ||
    safe(room?.invitedPlayerId) === safe(playerId);
}

async function actionSocialSessionIssue(event, body) {
  if (!CFG.socialSessionSecret) throw new Error('social_session_not_configured');

  const identity = await verifyYandexOAuth(event, body);
  const issuedAt = now();
  const expiresAt = issuedAt + CFG.socialSessionTtlMs;

  const oldPlayer = payload(await kvGet(`player:${identity.friendId}`));
  const oldProfile = payload(await kvGet(`profile:${identity.friendId}`));

  await kvPut({
    pk: `player:${identity.friendId}`,
    type: 'player',
    owner: identity.friendId,
    data: {
      ...oldPlayer,
      playerId: identity.friendId,
      authVersion: 2,
      yandexIdHash: hash(`ya:${identity.yandexId}`),
      displayName: identity.displayName,
      avatarUrl: identity.avatarUrl,
      createdAt: oldPlayer.createdAt || issuedAt,
      updatedAt: issuedAt
    }
  });

  await kvPut({
    pk: `profile:${identity.friendId}`,
    type: 'profile',
    owner: identity.friendId,
    data: {
      ...oldProfile,
      friendId: identity.friendId,
      displayName: identity.displayName || oldProfile.displayName || 'Слушатель',
      avatarUrl: identity.avatarUrl || oldProfile.avatarUrl || '',
      updatedAt: issuedAt
    }
  });

  const session = issueSocialSession({
    sub: identity.friendId,
    yidHash: hash(`ya:${identity.yandexId}`),
    iat: issuedAt,
    exp: expiresAt,
    jti: rid('ss'),
    v: 2
  });

  return {
    ok: true,
    friendId: identity.friendId,
    socialSession: session,
    expiresAt,
    profile: {
      friendId: identity.friendId,
      displayName: identity.displayName,
      avatarUrl: identity.avatarUrl
    }
  };
}

async function requirePlayer(event, body) {
  const token = headerValue(event, 'x-vi3-session');
  if (!token) throw new Error('social_session_required');

  const claims = verifySocialSession(token);
  const requestedId = sanitizeId(
    body.playerId ||
    body.userId ||
    ''
  );

  if (requestedId && requestedId !== claims.sub) {
    throw new Error('player_identity_mismatch');
  }

  const row = await kvGet(`player:${claims.sub}`);
  if (!row) throw new Error('player_not_registered');

  return {
    playerId: claims.sub,
    sessionId: safe(claims.jti),
    expiresAt: num(claims.exp),
    authVersion: 2
  };
}

async function actionPlayerRegister(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const old = payload(await kvGet(`player:${playerId}`));

  await kvPut({
    pk: `player:${playerId}`,
    type: 'player',
    owner: playerId,
    data: {
      ...old,
      playerId,
      authVersion: Math.max(2, num(old.authVersion)),
      displayName: safe(body.displayName || old.displayName || 'Игрок').slice(0, 80),
      avatarUrl: safe(body.avatarUrl || old.avatarUrl || '').slice(0, 400),
      updatedAt: now(),
      createdAt: old.createdAt || now()
    }
  });

  return { ok: true, playerId };
}

async function actionHeartbeat(event, body) {
  const { playerId } = await requirePlayer(event, body);
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
  const { friendId: targetId } = await requireFriendContext(event, body, {
    friendFields: ['targetId', 'friendId']
  });

  const rows = await kvPrefix(`presence:${targetId}:`, 20);
  const best = rows
    .map(payload)
    .sort((a, b) => num(b.onlineUntil) - num(a.onlineUntil))[0] || null;

  return {
    ok: true,
    online: !!best && num(best.onlineUntil) > now(),
    lastSeenAt: num(best?.updatedAt),
    currentGameId: safe(best?.currentGameId || ''),
    currentRoomId: safe(best?.currentRoomId || '')
  };
}

async function actionFriendInviteCreate(event, body) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'friend_invite',
    actor: playerId,
    limit: 10,
    windowMs: 60 * 60 * 1000
  });

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
  const { playerId } = await requirePlayer(event, body);
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
  const { playerId } = await requirePlayer(event, body);
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
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);

  if (!row || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }

  if (room.status === 'closed' || num(room.closedAt) > 0) {
    return { ok: false, reason: 'room_closed' };
  }

  if (num(room.reconnectUntil) > 0 && num(room.reconnectUntil) < now()) {
    return { ok: false, reason: 'room_expired' };
  }

  const requestedPeerId = sanitizeId(body.peerId || '', 120);

  if (
    room.invitedPlayerId &&
    room.invitedPlayerId !== playerId &&
    room.hostPlayerId !== playerId
  ) {
    return { ok: false, reason: 'room_invite_forbidden' };
  }

  if (room.guestPlayerId && room.guestPlayerId !== playerId) {
    return { ok: false, reason: 'room_already_has_guest' };
  }

  if (
    room.guestPlayerId === playerId &&
    room.guestPeerId &&
    requestedPeerId &&
    room.guestPeerId !== requestedPeerId
  ) {
    return { ok: false, reason: 'room_busy' };
  }

  room.guestPlayerId = playerId;
  room.guestPeerId =
    requestedPeerId ||
    sanitizeId(room.guestPeerId || `${roomId}:guest`, 120) ||
    `${roomId}:guest`;
  room.status = room.status === 'waiting' ? 'accepted' : room.status;
  room.updatedAt = now();

  await kvPut({
    pk: `room:${roomId}`,
    type: 'room',
    owner: room.hostPlayerId,
    expiresAt: room.reconnectUntil || now() + CFG.roomTtlMs,
    data: room
  });

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
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);

  if (!row || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }

  if (!isRoomViewer(room, playerId)) {
    return { ok: false, reason: 'room_forbidden' };
  }

  return { ok: true, room };
}

async function actionRoomClose(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);

  if (!row) return { ok: true, closed: false };
  if (room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }
  if (!isRoomParticipant(room, playerId)) {
    return { ok: false, reason: 'room_forbidden' };
  }

  room.status = 'closed';
  room.closedAt = now();
  room.closedByPlayerId = playerId;
  room.updatedAt = now();

  await kvPut({
    pk: `room:${roomId}`,
    type: 'room',
    owner: room.hostPlayerId || '',
    expiresAt: now() + 600000,
    data: room
  });

  return { ok: true, closed: true };
}

async function actionRoomSetMode(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const row = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(row);

  if (!row || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };
  if (room.hostPlayerId !== playerId) {
    return { ok: false, reason: 'room_host_required' };
  }
  if (room.status === 'closed') return { ok: false, reason: 'room_closed' };

  const ranked = body.ranked === true;
  room.ranked = ranked;
  room.matchMode = ranked ? 'ranked' : 'casual';
  room.localOnly = body.localOnly === false ? !!room.localOnly : true;
  room.modeChangedByPlayerId = playerId;
  room.modeChangedAt = now();
  room.updatedAt = now();

  await kvPut({
    pk: `room:${roomId}`,
    type: 'room',
    owner: room.hostPlayerId || playerId,
    expiresAt: room.reconnectUntil || now() + CFG.roomTtlMs,
    data: room
  });

  return {
    ok: true,
    roomId,
    ranked: !!room.ranked,
    localOnly: !!room.localOnly,
    matchMode: room.matchMode
  };
}

async function actionSignalSend(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const fromPeerId = sanitizeId(body.fromPeerId || body.peerId, 140);
  const toPeerId = sanitizeId(body.toPeerId || body.targetPeerId, 140);
  const type = sanitizeId(body.type || body.signalType || body.payload?.type, 40);
  const payloadData = body.payload?.data !== undefined ? body.payload.data : body.payload;

  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);

  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }
  if (room.status === 'closed' || num(room.closedAt) > 0) {
    return { ok: false, reason: 'room_closed' };
  }
  if (!isRoomParticipant(room, playerId)) {
    return { ok: false, reason: 'room_forbidden' };
  }
  if (!toPeerId || !fromPeerId || !type) {
    throw new Error('bad_signal');
  }

  const expectedFromPeerId = expectedPeerForPlayer(room, playerId);
  const allowedPeers = new Set(
    [room.hostPeerId, room.guestPeerId].filter(Boolean)
  );

  if (!expectedFromPeerId || fromPeerId !== expectedFromPeerId) {
    return { ok: false, reason: 'peer_identity_mismatch' };
  }
  if (!allowedPeers.has(toPeerId) || toPeerId === fromPeerId) {
    return { ok: false, reason: 'peer_target_forbidden' };
  }

  const seq = `${now().toString().padStart(13, '0')}_${crypto.randomBytes(4).toString('hex')}`;
  const expiresAt = now() + CFG.signalTtlMs;

  await kvPut({
    pk: `signal:${roomId}:${toPeerId}:${seq}`,
    type: 'signal',
    owner: toPeerId,
    expiresAt,
    data: {
      seq,
      status: 'pending',
      deliveredAt: 0,
      deliveryAttempts: 0,
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
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const peerId = sanitizeId(body.peerId, 140);

  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);
  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }
  if (room.status === 'closed' || num(room.closedAt) > 0) {
    return { ok: false, reason: 'room_closed' };
  }
  if (!isRoomParticipant(room, playerId)) {
    return { ok: false, reason: 'room_forbidden' };
  }
  if (!peerId) throw new Error('peer_id_required');
  if (expectedPeerForPlayer(room, playerId) !== peerId) {
    return { ok: false, reason: 'peer_identity_mismatch' };
  }

  const rows = await kvPrefix(`signal:${roomId}:${peerId}:`, 200);
  const messages = [];

  for (const row of rows) {
    const msg = payload(row);

    if (!msg.deliveredAt) {
      msg.status = 'delivered';
      msg.deliveredAt = now();
      msg.deliveryAttempts = num(msg.deliveryAttempts) + 1;

      await kvPut({
        pk: row.pk,
        type: 'signal',
        owner: peerId,
        expiresAt: num(row.expires_at) || num(msg.expiresAt),
        data: msg
      });
    }

    messages.push(msg);
  }

  messages.sort((a, b) => num(a.createdAt) - num(b.createdAt));
  return { ok: true, messages };
}
async function actionSignalAck(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const peerId = sanitizeId(body.peerId, 140);
  const seqs = [...new Set(
    (Array.isArray(body.seqs) ? body.seqs : [body.seq])
      .map(x => sanitizeId(x, 140))
      .filter(Boolean)
      .slice(0, 200)
  )];

  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);

  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }
  if (!isRoomParticipant(room, playerId)) {
    return { ok: false, reason: 'room_forbidden' };
  }
  if (expectedPeerForPlayer(room, playerId) !== peerId) {
    return { ok: false, reason: 'peer_identity_mismatch' };
  }

  await Promise.all(
    seqs.map(seq =>
      kvDelete(`signal:${roomId}:${peerId}:${seq}`).catch(() => null)
    )
  );

  return { ok: true, acked: seqs.length };
}
async function actionGameInviteCreate(event, body) {
  const {
    playerId,
    friendId: toPlayerId
  } = await requireFriendContext(event, body, {
    friendFields: ['toPlayerId', 'friendId']
  });
  const gameId = sanitizeId(body.gameId || 'game', 80);

  const gameInviteId = rid('gi');
  const expiresAt = now() + CFG.gameInviteTtlMs;

  const invite = {
    gameInviteId,
    gameId,
    fromPlayerId: playerId,
    toPlayerId,
    status: 'pending',
    createdAt: now(),
    updatedAt: now(),
    expiresAt
  };

  await Promise.all([
    kvPut({
      pk: `gameInvite:${gameInviteId}`,
      type: 'gameInvite',
      owner: toPlayerId,
      expiresAt,
      data: invite
    }),
    kvPut({
      pk: `gameInviteInbox:${toPlayerId}:${gameInviteId}`,
      type: 'gameInviteInbox',
      owner: toPlayerId,
      expiresAt,
      data: invite
    }),
    kvPut({
      pk: `gameInviteOutbox:${playerId}:${gameInviteId}`,
      type: 'gameInviteOutbox',
      owner: playerId,
      expiresAt,
      data: invite
    })
  ]);

  return { ok: true, gameInviteId, expiresAt };
}

async function actionGameInvitePoll(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const [inbox, outbox] = await Promise.all([
    kvPrefix(`gameInviteInbox:${playerId}:`, 100),
    kvPrefix(`gameInviteOutbox:${playerId}:`, 100)
  ]);

  const items = [...new Map(
    [...inbox, ...outbox]
      .map(payload)
      .filter(item => item?.gameInviteId)
      .map(item => [item.gameInviteId, item])
  ).values()].sort((a, b) => num(a.createdAt) - num(b.createdAt));

  return { ok: true, items };
}

async function actionGameInviteSet(event, body, status) {
  const { playerId } = await requirePlayer(event, body);
  const gameInviteId = sanitizeId(body.gameInviteId || body.inviteId);
  const row = gameInviteId ? await kvGet(`gameInvite:${gameInviteId}`) : null;
  const inv = payload(row);
  if (!row) return { ok: false, reason: 'invite_not_found' };
  if (![inv.toPlayerId, inv.fromPlayerId].includes(playerId)) throw new Error('invite_forbidden');

  inv.status = status;
  inv.updatedAt = now();
  if (status === 'accepted') inv.acceptedAt = now();
  if (status === 'rejected') inv.rejectedAt = now();

  await Promise.all([
    kvPut({
      pk: `gameInvite:${gameInviteId}`,
      type: 'gameInvite',
      owner: inv.toPlayerId,
      expiresAt: inv.expiresAt,
      data: inv
    }),
    kvPut({
      pk: `gameInviteInbox:${inv.toPlayerId}:${gameInviteId}`,
      type: 'gameInviteInbox',
      owner: inv.toPlayerId,
      expiresAt: inv.expiresAt,
      data: inv
    }),
    kvPut({
      pk: `gameInviteOutbox:${inv.fromPlayerId}:${gameInviteId}`,
      type: 'gameInviteOutbox',
      owner: inv.fromPlayerId,
      expiresAt: inv.expiresAt,
      data: inv
    })
  ]);

  return { ok: true, invite: inv };
}

// ===== FRIENDS MODULE (Phase A) =====

async function actionProfileSet(event, body) {
  const { playerId } = await requirePlayer(event, body);

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
  const { friendId: targetId } = await requireFriendContext(event, body, {
    friendFields: ['targetId', 'friendId']
  });

  const row = await kvGet(`profile:${targetId}`);
  const data = payload(row);

  return {
    ok: true,
    profile: data && data.friendId ? data : null
  };
}

async function actionFriendList(event, body) {
  const { playerId } = await requirePlayer(event, body);

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
  const {
    playerId,
    friendId: targetId
  } = await requireFriendContext(event, body, {
    friendFields: ['targetId', 'friendId']
  });

  await Promise.all([
    kvDelete(`friend:${playerId}:${targetId}`).catch(() => null),
    kvDelete(`friend:${targetId}:${playerId}`).catch(() => null)
  ]);

  return { ok: true, removed: true };
}

async function actionPresenceBatch(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const requested = [...new Set(
    (Array.isArray(body.friendIds) ? body.friendIds : [])
      .map(id => sanitizeId(id))
      .filter(id => id && id !== playerId)
  )].slice(0, 50);

  const allowed = await getActiveFriendIdSet(playerId);
  const ids = requested.filter(id => allowed.has(id));
  const presence = {};
  const t = now();

  for (const id of ids) {
    const rows = await kvPrefix(`presence:${id}:`, 10);
    const best = rows
      .map(payload)
      .sort((a, b) => num(b.onlineUntil) - num(a.onlineUntil))[0] || null;

    presence[id] = {
      online: !!best && num(best.onlineUntil) > t
    };
  }

  return { ok: true, presence };
}

async function sendSystemWebPush({
  toPlayerId,
  title,
  body,
  url = './',
  tag = 'vi3-notification',
  requireInteraction = false,
  kind = '',
  fromFriendId = '',
  gameId = '',
  msgId = '',
  callId = ''
} = {}) {
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
        playerId: toPlayerId,
        title,
        body,
        url,
        tag,
        requireInteraction,
        kind,
        fromFriendId,
        gameId,
        msgId,
        callId
      })
    });

    const json = await res.json().catch(() => ({}));
    return json;
  } catch (err) {
    return { ok: false, error: safe(err.message || err) };
  }
}

async function actionPushSend(event, body) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'push_send',
    actor: playerId,
    limit: 20,
    windowMs: 60 * 1000
  });

  const toFriendId = await requireFriendship(
    playerId,
    body.toFriendId || body.toPlayerId
  );

  const pushId = rid('push');
  const kind = safe(body.kind || 'GENERIC').slice(0, 40);
  const gameId = sanitizeId(body.gameId || '');
  const roomId = sanitizeId(body.roomId || '');
  const roomSecret = safe(body.roomSecret || '');
  const text = safe(body.text || '').slice(0, 300);
  const createdAt = now();
  const expiresAt = kind === 'GAME_INVITE'
    ? createdAt + Math.max(30000, Math.min(CFG.gameInviteTtlMs || 30000, 120000))
    : createdAt + 7 * 24 * 60 * 60 * 1000;

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

  const isGameInvite = kind === 'GAME_INVITE';
  const webPush = await sendSystemWebPush({
    toPlayerId: toFriendId,
    title: `${isGameInvite ? '🎮' : '🔔'} ${fromName}`,
    body: isGameInvite
      ? 'Приглашение: Война Сердец'
      : 'Ждёт вас в приложении',
    url: './?openFriends=1',
    tag: isGameInvite ? `game-${roomId || pushId}` : `push-${pushId}`,
    requireInteraction: true,
    kind,
    fromFriendId: playerId,
    gameId
  });

  return { ok: true, pushId, webPush };
}

async function actionPushPoll(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const deviceId = sanitizeId(body.deviceId, 120);

  if (!deviceId) {
    throw new Error('push_device_required');
  }

  const rows = await kvPrefix(`push:${playerId}:`, 100);
  const t = now();
  const items = [];

  for (const row of rows) {
    const item = payload(row);
    const exp = num(item.expiresAt);
    const age = t - num(item.createdAt);

    const stale =
      (exp && exp < t) ||
      (item.kind === 'GAME_INVITE' && age > 120000) ||
      (item.kind === 'VOICE_CALL' && age > 120000);

    if (stale) {
      await kvDelete(row.pk).catch(() => null);
      continue;
    }

    const pushId = sanitizeId(item.pushId, 120);
    if (!pushId) continue;

    const ack = await kvGet(
      `pushAck:${playerId}:${deviceId}:${pushId}`
    );

    if (ack) continue;

    items.push(item);
  }

  items.sort((a, b) =>
    num(a.createdAt) - num(b.createdAt)
  );

  return {
    ok: true,
    deviceId,
    items
  };
}

async function actionPushAck(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const deviceId = sanitizeId(body.deviceId, 120);

  if (!deviceId) {
    throw new Error('push_device_required');
  }

  const ids = [...new Set(
    (Array.isArray(body.pushIds)
      ? body.pushIds
      : [body.pushId])
      .map(value => sanitizeId(value, 120))
      .filter(Boolean)
  )].slice(0, 100);

  if (!ids.length) {
    return { ok: true, acked: 0 };
  }

  const at = now();
  const expiresAt = at + 7 * 24 * 60 * 60 * 1000;

  await Promise.all(ids.map(pushId =>
    kvPut({
      pk: `pushAck:${playerId}:${deviceId}:${pushId}`,
      type: 'pushAck',
      owner: playerId,
      expiresAt,
      data: {
        playerId,
        deviceId,
        pushId,
        ackedAt: at
      }
    })
  ));

  return {
    ok: true,
    deviceId,
    acked: ids.length
  };
}

function chatRoomId(a, b) {
  return [sanitizeId(a), sanitizeId(b)].sort().join(':');
}

const CHAT_RETENTION_DAYS = new Set([1, 7, 30]);

function normalizeRetentionDays(value) {
  const days = Math.floor(num(value, 30));
  return CHAT_RETENTION_DAYS.has(days) ? days : 30;
}

async function getChatPreference(room, playerId) {
  const row = await kvGet(`chatPref:${room}:${playerId}`);
  const data = payload(row);

  return {
    retentionDays: normalizeRetentionDays(data.retentionDays),
    clearedBefore: num(data.clearedBefore),
    updatedAt: num(data.updatedAt)
  };
}

async function getChatRoomState(room) {
  const row = await kvGet(`chatRoom:${room}`);
  const data = payload(row);

  return {
    purgeBefore: num(data.purgeBefore),
    purgeId: safe(data.purgeId),
    purgedBy: sanitizeId(data.purgedBy),
    updatedAt: num(data.updatedAt)
  };
}

async function setChatPurgeBarrier(room, playerId) {
  const at = now();
  const state = {
    purgeBefore: at,
    purgeId: rid('purge'),
    purgedBy: playerId,
    updatedAt: at
  };

  await kvPut({
    pk: `chatRoom:${room}`,
    type: 'chatRoom',
    owner: room,
    data: state
  });

  return state;
}

async function deleteChatRowsThrough(room, cutoff, batchSize = 300, maxBatches = 20) {
  let deleted = 0;

  for (let batch = 0; batch < maxBatches; batch++) {
    const rows = await kvPrefix(`chat:${room}:`, batchSize);
    const targets = rows.filter(row =>
      num(payload(row).createdAt) <= num(cutoff)
    );

    if (!targets.length) break;

    await Promise.all(
      targets.flatMap(row => {
        const message = payload(row);
        return [
          kvDelete(row.pk).catch(() => null),
          message.msgId
            ? kvDelete(`chatById:${room}:${message.msgId}`).catch(() => null)
            : Promise.resolve(),
          message.clientMsgId && message.fromFriendId
            ? kvDelete(
              `chatClient:${room}:${message.fromFriendId}:${message.clientMsgId}`
            ).catch(() => null)
            : Promise.resolve(),
          message.msgId
            ? kvDelete(
              `chatReceipt:${room}:${message.msgId}`
            ).catch(() => null)
            : Promise.resolve()
        ];
      })
    );

    deleted += targets.length;
    if (targets.length < batchSize) break;
  }

  return deleted;
}

function normalizePublicJwk(raw) {
  const jwk = raw && typeof raw === 'object' ? raw : {};
  const out = {
    kty: safe(jwk.kty),
    crv: safe(jwk.crv),
    x: safe(jwk.x),
    y: safe(jwk.y),
    ext: true
  };

  if (
    out.kty !== 'EC' ||
    out.crv !== 'P-256' ||
    !/^[A-Za-z0-9_-]{40,60}$/.test(out.x) ||
    !/^[A-Za-z0-9_-]{40,60}$/.test(out.y)
  ) {
    throw new Error('bad_crypto_public_key');
  }

  return out;
}

function publicKeyFingerprint(jwk) {
  return base64url(
    crypto.createHash('sha256')
      .update(`${jwk.crv}:${jwk.x}:${jwk.y}`, 'utf8')
      .digest()
  );
}

async function getCryptoDevices(playerId, { activeOnly = true } = {}) {
  const rows = await kvPrefix(`cryptoDevice:${sanitizeId(playerId)}:`, 30);
  return rows
    .map(payload)
    .filter(item => item?.deviceId)
    .filter(item => !activeOnly || !item.revokedAt)
    .sort((a, b) => num(a.createdAt) - num(b.createdAt));
}

function normalizeCryptoPack(raw) {
  const pack = raw && typeof raw === 'object' ? raw : {};
  const envelopes = (Array.isArray(pack.envelopes) ? pack.envelopes : [])
    .slice(0, 30)
    .map(item => ({
      ownerId: sanitizeId(item?.ownerId),
      deviceId: sanitizeId(item?.deviceId, 120),
      wrapIv: safe(item?.wrapIv),
      wrappedKey: safe(item?.wrappedKey)
    }));

  if (
    num(pack.version) !== 2 ||
    safe(pack.algorithm) !== 'ECDH-P256+HKDF-SHA256+AES-256-GCM' ||
    !sanitizeId(pack.senderDeviceId, 120) ||
    !safe(pack.aad) ||
    !safe(pack.iv) ||
    !safe(pack.kdfSalt) ||
    !safe(pack.ciphertext) ||
    !envelopes.length
  ) {
    throw new Error('bad_crypto_payload');
  }

  if (
    safe(pack.ciphertext).length > 24000 ||
    safe(pack.aad).length > 1600 ||
    safe(pack.kdfSalt).length > 100 ||
    safe(pack.iv).length > 100 ||
    envelopes.some(item =>
      !item.ownerId ||
      !item.deviceId ||
      item.wrapIv.length > 100 ||
      item.wrappedKey.length > 300
    )
  ) {
    throw new Error('bad_crypto_payload_size');
  }

  return {
    version: 2,
    algorithm: 'ECDH-P256+HKDF-SHA256+AES-256-GCM',
    senderDeviceId: sanitizeId(pack.senderDeviceId, 120),
    senderPublicJwk: normalizePublicJwk(pack.senderPublicJwk),
    senderFingerprint: safe(pack.senderFingerprint).slice(0, 100),
    clientMsgId: sanitizeId(pack.clientMsgId, 120),
    aad: safe(pack.aad),
    iv: safe(pack.iv),
    kdfSalt: safe(pack.kdfSalt),
    ciphertext: safe(pack.ciphertext),
    envelopes
  };
}

function decodeCryptoAad(encoded) {
  let data;

  try {
    data = JSON.parse(base64urlDecode(encoded).toString('utf8'));
  } catch {
    throw new Error('bad_crypto_aad');
  }

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('bad_crypto_aad');
  }

  return {
    v: num(data.v),
    kind: sanitizeId(data.kind, 40),
    room: safe(data.room),
    fromFriendId: sanitizeId(data.fromFriendId),
    toFriendId: sanitizeId(data.toFriendId),
    clientMsgId: sanitizeId(data.clientMsgId, 120),
    subjectMsgId: sanitizeId(data.subjectMsgId, 96),
    senderDeviceId: sanitizeId(data.senderDeviceId, 120)
  };
}

function validateCryptoAad({
  pack,
  room,
  playerId,
  friendId,
  kind,
  clientMsgId = '',
  subjectMsgId = ''
}) {
  const aad = decodeCryptoAad(pack.aad);

  if (aad.v !== 2) throw new Error('bad_crypto_aad_version');
  if (aad.kind !== sanitizeId(kind, 40)) {
    throw new Error('bad_crypto_aad_kind');
  }
  if (aad.room !== room) {
    throw new Error('bad_crypto_aad_room');
  }
  if (aad.fromFriendId !== playerId) {
    throw new Error('bad_crypto_aad_sender');
  }
  if (aad.toFriendId !== friendId) {
    throw new Error('bad_crypto_aad_recipient');
  }
  if (aad.senderDeviceId !== pack.senderDeviceId) {
    throw new Error('bad_crypto_aad_device');
  }
  if (aad.clientMsgId !== sanitizeId(clientMsgId || pack.clientMsgId, 120)) {
    throw new Error('bad_crypto_aad_client_message');
  }
  if (aad.subjectMsgId !== sanitizeId(subjectMsgId, 96)) {
    throw new Error('bad_crypto_aad_subject');
  }

  return aad;
}

async function validateCryptoPack({
  pack,
  playerId,
  friendId,
  room,
  kind,
  clientMsgId = '',
  subjectMsgId = ''
}) {
  const normalized = normalizeCryptoPack(pack);
  const senderDevices = await getCryptoDevices(playerId);
  const senderDevice = senderDevices.find(item =>
    item.deviceId === normalized.senderDeviceId
  );

  if (!senderDevice) throw new Error('crypto_sender_device_required');

  const actualFingerprint = publicKeyFingerprint(
    normalized.senderPublicJwk
  );

  if (
    actualFingerprint !== senderDevice.fingerprint ||
    normalized.senderFingerprint !== senderDevice.fingerprint
  ) {
    throw new Error('crypto_sender_key_mismatch');
  }

  const [myDevices, friendDevices] = await Promise.all([
    getCryptoDevices(playerId),
    getCryptoDevices(friendId)
  ]);

  if (!myDevices.length || !friendDevices.length) {
    throw new Error('crypto_devices_missing');
  }

  const expected = new Set(
    [...myDevices, ...friendDevices]
      .map(item => `${item.ownerId}:${item.deviceId}`)
  );
  const received = new Set(
    normalized.envelopes
      .map(item => `${item.ownerId}:${item.deviceId}`)
  );

  if (
    expected.size !== received.size ||
    [...expected].some(key => !received.has(key))
  ) {
    throw new Error('crypto_envelope_coverage_mismatch');
  }

  const envelopeKeys = normalized.envelopes.map(item =>
    `${item.ownerId}:${item.deviceId}`
  );

  if (new Set(envelopeKeys).size !== envelopeKeys.length) {
    throw new Error('crypto_duplicate_envelope');
  }

  if (normalized.envelopes.some(item =>
    item.ownerId !== playerId && item.ownerId !== friendId
  )) {
    throw new Error('crypto_foreign_envelope');
  }

  validateCryptoAad({
    pack: normalized,
    room,
    playerId,
    friendId,
    kind,
    clientMsgId,
    subjectMsgId
  });

  return normalized;
}

async function actionCryptoDeviceRegister(event, body) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'crypto_register',
    actor: playerId,
    limit: 8,
    windowMs: 10 * 60 * 1000
  });

  if (!CFG.chatE2eeV2) {
    throw new Error('chat_e2ee_disabled');
  }

  const deviceId = sanitizeId(body.deviceId, 120);
  if (!deviceId) throw new Error('crypto_device_required');

  const publicJwk = normalizePublicJwk(body.publicJwk);
  const fingerprint = publicKeyFingerprint(publicJwk);
  const suppliedFingerprint = safe(body.fingerprint);

  if (suppliedFingerprint && suppliedFingerprint !== fingerprint) {
    throw new Error('crypto_fingerprint_mismatch');
  }

  const pk = `cryptoDevice:${playerId}:${deviceId}`;
  const old = payload(await kvGet(pk));
  if (
    old?.fingerprint &&
    old.fingerprint !== fingerprint &&
    !old.revokedAt
  ) {
    throw new Error('crypto_device_key_conflict');
  }

  const deviceStableId = sanitizeId(
    body.deviceStableId || '',
    120
  );
  const registeredAt = now();

  if (deviceStableId) {
    const rows = await kvPrefix(
      `cryptoDevice:${playerId}:`,
      100
    );

    await Promise.all(rows.map(async row => {
      const item = payload(row);

      if (
        !item.deviceId ||
        item.deviceId === deviceId ||
        item.revokedAt ||
        item.deviceStableId !== deviceStableId
      ) return;

      item.revokedAt = registeredAt;
      item.updatedAt = registeredAt;

      await kvPut({
        pk: row.pk,
        type: 'cryptoDevice',
        owner: playerId,
        expiresAt:
          registeredAt +
          30 * 24 * 60 * 60 * 1000,
        data: item
      });
    }));
  }

  const active = await getCryptoDevices(playerId);
  if (
    !active.some(item => item.deviceId === deviceId) &&
    active.length >= 12
  ) {
    const error = new Error('crypto_device_limit');
    error.httpStatus = 409;
    throw error;
  }

  const data = {
    ownerId: playerId,
    deviceId,
    publicJwk,
    fingerprint,
    label: safe(body.label || 'Устройство').slice(0, 80),
    deviceStableId,
    createdAt: old.createdAt || registeredAt,
    updatedAt: registeredAt,
    revokedAt: 0
  };

  await kvPut({
    pk,
    type: 'cryptoDevice',
    owner: playerId,
    data
  });

  return { ok: true, device: data };
}

async function actionCryptoDeviceList(event, body) {
  const {
    playerId,
    friendId
  } = await requireFriendContext(event, body);

  const [mine, peer] = await Promise.all([
    getCryptoDevices(playerId),
    getCryptoDevices(friendId)
  ]);

  return {
    ok: true,
    items: [...mine, ...peer].map(item => ({
      ownerId: item.ownerId,
      deviceId: item.deviceId,
      publicJwk: item.publicJwk,
      fingerprint: item.fingerprint,
      label: item.label,
      createdAt: item.createdAt
    }))
  };
}

async function actionCryptoDeviceRevoke(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const deviceId = sanitizeId(body.deviceId, 120);
  if (!deviceId) throw new Error('crypto_device_required');

  const pk = `cryptoDevice:${playerId}:${deviceId}`;
  const row = await kvGet(pk);
  const data = payload(row);

  if (!row || data.ownerId !== playerId) {
    throw new Error('crypto_device_not_found');
  }

  data.revokedAt = now();
  data.updatedAt = data.revokedAt;

  await kvPut({
    pk,
    type: 'cryptoDevice',
    owner: playerId,
    expiresAt: data.revokedAt + 30 * 24 * 60 * 60 * 1000,
    data
  });

  return {
    ok: true,
    revoked: true,
    deviceId
  };
}

async function actionCryptoDeviceSelfList(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const items = await getCryptoDevices(playerId, {
    activeOnly: false
  });

  return {
    ok: true,
    items: items.map(item => ({
      ownerId: item.ownerId,
      deviceId: item.deviceId,
      deviceStableId: item.deviceStableId || '',
      publicJwk: item.publicJwk,
      fingerprint: item.fingerprint,
      label: item.label,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
      revokedAt: item.revokedAt || 0
    }))
  };
}

async function actionCryptoDeviceReset(event, body) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'crypto_reset',
    actor: playerId,
    limit: 3,
    windowMs: 24 * 60 * 60 * 1000
  });

  const rows = await kvPrefix(`cryptoDevice:${playerId}:`, 100);
  const at = now();
  let revoked = 0;

  for (const row of rows) {
    const data = payload(row);
    if (!data.deviceId || data.revokedAt) continue;

    data.revokedAt = at;
    data.updatedAt = at;

    await kvPut({
      pk: row.pk,
      type: 'cryptoDevice',
      owner: playerId,
      expiresAt: at + 30 * 24 * 60 * 60 * 1000,
      data
    });

    revoked++;
  }

  return {
    ok: true,
    revoked,
    resetAt: at,
    historyReadable: false
  };
}

async function findChatRow(room, msgId) {
  const indexRow = await kvGet(
    `chatById:${room}:${msgId}`
  );
  const index = payload(indexRow);

  if (!index?.chatPk) return null;

  const row = await kvGet(index.chatPk);
  return row && payload(row)?.msgId === msgId
    ? row
    : null;
}

async function requireChatMessageContext(event, body, {
  cryptoVersion = 0
} = {}) {
  const context = await requireFriendContext(event, body);
  const msgId = sanitizeId(body.msgId, 96);

  if (!msgId) throw new Error('msg_required');

  const row = await findChatRow(context.room, msgId);
  if (!row) throw new Error('chat_message_not_found');

  const message = payload(row);
  const participants = new Set([
    safe(message.fromFriendId),
    safe(message.toFriendId)
  ]);

  if (
    !participants.has(context.playerId) ||
    !participants.has(context.friendId)
  ) {
    throw new Error('chat_message_forbidden');
  }

  if (
    cryptoVersion > 0 &&
    num(message.cryptoVersion) !== cryptoVersion
  ) {
    throw new Error('chat_crypto_version_mismatch');
  }

  return {
    ...context,
    row,
    message,
    msgId
  };
}

function publicChatMessage(message, receipt = null) {
  const {
    deliveredAt: legacyDeliveredAt,
    readAt: legacyReadAt,
    ...data
  } = message || {};

  return {
    ...data,
    deliveredAt: Math.max(
      num(receipt?.deliveredAt),
      num(legacyDeliveredAt)
    ),
    readAt: Math.max(
      num(receipt?.readAt),
      num(legacyReadAt)
    )
  };
}

async function getChatReceiptMap(room) {
  const rows = await kvPrefix(
    `chatReceipt:${room}:`,
    300
  );

  return new Map(rows
    .map(payload)
    .filter(item => item?.msgId)
    .map(item => [item.msgId, item]));
}

async function putChatReceipt({
  room,
  message,
  playerId,
  kind
}) {
  const pk = `chatReceipt:${room}:${message.msgId}`;
  const old = payload(await kvGet(pk));
  const at = now();

  const receipt = {
    room,
    msgId: message.msgId,
    fromFriendId: message.fromFriendId,
    toFriendId: message.toFriendId,
    deliveredAt:
      old.deliveredAt ||
      (kind === 'delivered' || kind === 'read' ? at : 0),
    readAt:
      old.readAt ||
      (kind === 'read' ? at : 0),
    updatedBy: playerId,
    updatedAt: at
  };

  await kvPut({
    pk,
    type: 'chatReceipt',
    owner: message.toFriendId,
    expiresAt:
      num(message.createdAt) +
      30 * 24 * 60 * 60 * 1000,
    data: receipt
  });

  return receipt;
}

async function actionChatSendV2(event, body) {
  if (!CFG.chatE2eeV2) {
    throw new Error('chat_e2ee_disabled');
  }

  const {
    playerId,
    friendId: toFriendId,
    room
  } = await requireFriendContext(event, body, {
    friendFields: ['toFriendId', 'friendId']
  });

  await enforceRateLimit({
    scope: 'chat_send',
    actor: playerId,
    limit: 40,
    windowMs: 60 * 1000
  });

  const requestedClientMsgId = sanitizeId(
    body.clientMsgId || body.crypto?.clientMsgId,
    120
  );

  const cryptoPack = await validateCryptoPack({
    pack: body.crypto,
    playerId,
    friendId: toFriendId,
    room,
    kind: 'message',
    clientMsgId: requestedClientMsgId,
    subjectMsgId: ''
  });

  const createdAt = now();
  const msgId = rid('chat');
  const clientMsgId = requestedClientMsgId;

  if (!clientMsgId) {
    throw new Error('client_msg_id_required');
  }

  const duplicateRow = await kvGet(
    `chatClient:${room}:${playerId}:${clientMsgId}`
  );
  const duplicate = payload(duplicateRow);

  if (duplicate?.msgId) {
    return {
      ok: true,
      duplicate: true,
      msgId: duplicate.msgId,
      clientMsgId,
      cryptoVersion: 2,
      createdAt: num(duplicate.createdAt)
    };
  }
  
  const msg = {
    msgId,
    clientMsgId,
    room,
    fromFriendId: playerId,
    toFriendId,
    cryptoVersion: 2,
    crypto: cryptoPack,
    revision: 1,
    createdAt,
    updatedAt: createdAt,
    deletedAt: 0
  };

  const chatPk =
    `chat:${room}:${String(createdAt).padStart(13, '0')}:${msgId}`;

  const chatExpiresAt = createdAt + 30 * 24 * 60 * 60 * 1000;

  await Promise.all([
    kvPut({
      pk: chatPk,
      type: 'chat',
      owner: room,
      expiresAt: chatExpiresAt,
      data: msg
    }),
    kvPut({
      pk: `chatById:${room}:${msgId}`,
      type: 'chatById',
      owner: room,
      expiresAt: chatExpiresAt,
      data: {
        room,
        msgId,
        chatPk,
        clientMsgId,
        createdAt
      }
    }),
    kvPut({
      pk: `chatClient:${room}:${playerId}:${clientMsgId}`,
      type: 'chatClient',
      owner: playerId,
      expiresAt: chatExpiresAt,
      data: {
        room,
        msgId,
        chatPk,
        clientMsgId,
        createdAt
      }
    })
  ]);

  const roomState = await getChatRoomState(room);

  if (roomState.purgeBefore >= createdAt) {
    await Promise.all([
      kvDelete(chatPk).catch(() => null),
      kvDelete(`chatById:${room}:${msgId}`).catch(() => null),
      kvDelete(
        `chatClient:${room}:${playerId}:${clientMsgId}`
      ).catch(() => null)
    ]);

    return {
      ok: false,
      reason: 'chat_purged_during_send',
      retryable: true
    };
  }

  const pushId = rid('push');
  const expiresAt = createdAt + 7 * 24 * 60 * 60 * 1000;

  await kvPut({
    pk: `push:${toFriendId}:${String(createdAt).padStart(13, '0')}_${pushId}`,
    type: 'push',
    owner: toFriendId,
    expiresAt,
    data: {
      pushId,
      msgId,
      fromFriendId: playerId,
      kind: 'CHAT_MESSAGE',
      cryptoVersion: 2,
      createdAt,
      expiresAt
    }
  });

  const profile = payload(await kvGet(`profile:${playerId}`));
  const fromName = safe(
    profile.displayName ||
    body.displayName ||
    'Друг'
  ).slice(0, 80);

  const webPush = await sendSystemWebPush({
    toPlayerId: toFriendId,
    title: `💬 ${fromName}`,
    body: 'Новое сообщение',
    url: `./?openFriends=1&chatWith=${encodeURIComponent(playerId)}`,
    tag: `chat-${room}`,
    requireInteraction: true,
    kind: 'CHAT_MESSAGE',
    fromFriendId: playerId,
    msgId
  });

  return {
    ok: true,
    msgId,
    clientMsgId,
    cryptoVersion: 2,
    createdAt,
    webPush
  };
}

async function actionChatSettingsGet(event, body) {
  const { playerId, room } = await requireFriendContext(event, body);

  return {
    ok: true,
    settings: await getChatPreference(room, playerId)
  };
}

async function actionChatSettingsSet(event, body) {
  const { playerId, room } = await requireFriendContext(event, body);
  const old = await getChatPreference(room, playerId);
  const retentionDays = normalizeRetentionDays(body.retentionDays);

  const settings = {
    ...old,
    retentionDays,
    updatedAt: now()
  };

  await kvPut({
    pk: `chatPref:${room}:${playerId}`,
    type: 'chatPref',
    owner: playerId,
    data: settings
  });

  return { ok: true, settings };
}

async function actionChatPoll(event, body) {
  const { playerId, room } = await requireFriendContext(event, body);
  const after = num(body.after, 0);
  const [pref, roomState] = await Promise.all([
    getChatPreference(room, playerId),
    getChatRoomState(room)
  ]);

  const cutoff = Math.max(
    pref.clearedBefore,
    roomState.purgeBefore,
    now() - pref.retentionDays * 24 * 60 * 60 * 1000
  );
  const [rows, receipts] = await Promise.all([
    kvPrefix(`chat:${room}:`, 300),
    getChatReceiptMap(room)
  ]);

  const items = rows
    .map(payload)
    .filter(message =>
      num(message.cryptoVersion) === 2 &&
      num(message.createdAt) >= cutoff &&
      Math.max(
        num(message.createdAt),
        num(message.updatedAt),
        num(receipts.get(message.msgId)?.updatedAt)
      ) > after
    )
    .sort((a, b) =>
      num(a.createdAt) - num(b.createdAt)
    )
    .slice(-80)
    .map(message =>
      publicChatMessage(
        message,
        receipts.get(message.msgId)
      )
    );

  return { ok: true, items };
}

async function actionChatMessageGet(event, body) {
  const {
    room,
    message
  } = await requireChatMessageContext(event, body, {
    cryptoVersion: 2
  });

  const receipt = payload(await kvGet(
    `chatReceipt:${room}:${message.msgId}`
  ));

  return {
    ok: true,
    message: publicChatMessage(message, receipt)
  };
}

async function actionChatClear(event, body) {
  const { playerId, room } = await requireFriendContext(event, body);
  const old = await getChatPreference(room, playerId);
  const clearedBefore = now();

  await kvPut({
    pk: `chatPref:${room}:${playerId}`,
    type: 'chatPref',
    owner: playerId,
    data: {
      ...old,
      clearedBefore,
      updatedAt: clearedBefore
    }
  });

  return {
    ok: true,
    scope: 'self',
    clearedBefore
  };
}

async function actionChatPurgeBoth(event, body) {
  const {
    playerId,
    friendId,
    room
  } = await requireFriendContext(event, body);

  const barrier = await setChatPurgeBarrier(room, playerId);

  await Promise.all([
    kvPut({
      pk: `chatPref:${room}:${playerId}`,
      type: 'chatPref',
      owner: playerId,
      data: {
        retentionDays: 30,
        clearedBefore: barrier.purgeBefore,
        updatedAt: barrier.purgeBefore
      }
    }),
    kvPut({
      pk: `chatPref:${room}:${friendId}`,
      type: 'chatPref',
      owner: friendId,
      data: {
        retentionDays: 30,
        clearedBefore: barrier.purgeBefore,
        updatedAt: barrier.purgeBefore
      }
    })
  ]);

  const deleted = await deleteChatRowsThrough(
    room,
    barrier.purgeBefore
  );

  return {
    ok: true,
    scope: 'both',
    deleted,
    purgeId: barrier.purgeId,
    purgedAt: barrier.purgeBefore
  };
}

async function actionChatReceipt(event, body, receiptKind) {
  const {
    playerId,
    friendId,
    room
  } = await requireFriendContext(event, body);

  const msgId = sanitizeId(body.msgId || '', 96);
  let messages = [];

  if (msgId) {
    const row = await findChatRow(room, msgId);
    const message = payload(row);
    if (row) messages = [message];
  } else {
    messages = (await kvPrefix(`chat:${room}:`, 300))
      .map(payload);
  }

  const incoming = messages.filter(message =>
    num(message.cryptoVersion) === 2 &&
    message.fromFriendId === friendId &&
    message.toFriendId === playerId
  );

  await Promise.all(incoming.map(message =>
    putChatReceipt({
      room,
      message,
      playerId,
      kind: receiptKind
    })
  ));

  return {
    ok: true,
    updated: incoming.length,
    at: now()
  };
}

async function actionChatDelivered(event, body) {
  return actionChatReceipt(event, body, 'delivered');
}

async function actionChatRead(event, body) {
  return actionChatReceipt(event, body, 'read');
}

async function actionChatUpdateV2(event, body) {
  if (!CFG.chatE2eeV2) throw new Error('chat_e2ee_disabled');

  const {
    playerId,
    friendId,
    room,
    row,
    message: msg
  } = await requireChatMessageContext(event, body, {
    cryptoVersion: 2
  });
  const expectedRevision = Math.max(1, num(body.expectedRevision));
  if (num(msg.revision, 1) !== expectedRevision) {
    const error = new Error('chat_revision_conflict');
    error.httpStatus = 409;
    throw error;
  }
  msg.crypto = await validateCryptoPack({
    pack: body.crypto,
    playerId,
    friendId,
    room,
    kind: 'reaction',
    clientMsgId: body.crypto?.clientMsgId,
    subjectMsgId: msg.msgId
  });
  msg.revision = expectedRevision + 1;
  msg.updatedAt = now();

  const changed = await kvCompareAndPut({
    row,
    type: 'chat',
    owner: room,
    expiresAt: num(row.expires_at) ||
      num(msg.createdAt) + 30 * 24 * 60 * 60 * 1000,
    data: msg
  });

  if (!changed) {
    const error = new Error('chat_revision_conflict');
    error.httpStatus = 409;
    throw error;
  }

  return {
    ok: true,
    updated: 1,
    cryptoVersion: 2,
    revision: msg.revision,
    at: msg.updatedAt
  };
}

async function actionChatDeleteV2(event, body) {
  if (!CFG.chatE2eeV2) {
    throw new Error('chat_e2ee_disabled');
  }

  const {
    playerId,
    friendId,
    room,
    row,
    message: msg
  } = await requireChatMessageContext(event, body, {
    cryptoVersion: 2
  });

  const expectedRevision = Math.max(
    1,
    num(body.expectedRevision, 1)
  );

  if (num(msg.revision, 1) !== expectedRevision) {
    const error = new Error('chat_revision_conflict');
    error.httpStatus = 409;
    throw error;
  }

  msg.crypto = await validateCryptoPack({
    pack: body.crypto,
    playerId,
    friendId,
    room,
    kind: 'tombstone',
    clientMsgId: body.crypto?.clientMsgId,
    subjectMsgId: msg.msgId
  });

  msg.revision = expectedRevision + 1;
  msg.deletedAt = Math.max(
    num(body.deletedAt),
    now()
  );
  msg.updatedAt = msg.deletedAt;

  const changed = await kvCompareAndPut({
    row,
    type: 'chat',
    owner: room,
    expiresAt:
      num(row.expires_at) ||
      num(msg.createdAt) + 30 * 24 * 60 * 60 * 1000,
    data: msg
  });

  if (!changed) {
    const error = new Error('chat_revision_conflict');
    error.httpStatus = 409;
    throw error;
  }

  return {
    ok: true,
    deleted: 1,
    tombstone: true,
    revision: msg.revision,
    cryptoVersion: 2,
    at: msg.deletedAt
  };
}

async function saveVoiceLog({ callId, fromPlayerId, toPlayerId, roomId, status, startedAt = 0, endedAt = 0, durationSec = 0 } = {}) {
  const room = chatRoomId(fromPlayerId, toPlayerId);
  const at = now();
  const oldRow = callId ? await kvGet(`voice:${room}:${callId}`) : null;
  const old = payload(oldRow);

  const data = {
    ...old,
    callId,
    room,
    roomId,
    fromPlayerId,
    toPlayerId,
    status: safe(status || old.status || 'created'),
    createdAt: old.createdAt || at,
    startedAt: startedAt || old.startedAt || 0,
    endedAt: endedAt || old.endedAt || 0,
    durationSec: durationSec || old.durationSec || 0,
    updatedAt: at
  };

  await kvPut({
    pk: `voice:${room}:${callId}`,
    type: 'voice',
    owner: room,
    expiresAt: at + 90 * 24 * 60 * 60 * 1000,
    data
  });

  return data;
}

async function actionVoiceHistory(event, body) {
  const { room } = await requireFriendContext(event, body, {
    friendFields: ['friendId', 'withFriendId']
  });

  const rows = await kvPrefix(`voice:${room}:`, 100);
  const items = rows
    .map(payload)
    .sort((a, b) => num(a.createdAt) - num(b.createdAt))
    .slice(-50);

  return { ok: true, items };
}

async function actionVoiceCallCreate(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const toFriendId = await requireFriendship(
    playerId,
    body.toFriendId || body.friendId
  );

  const peerId = sanitizeId(body.peerId || `${playerId}:voice:${rid('p')}`, 140);
  const roomRes = await actionRoomCreate(event, {
    ...body,
    gameId: 'voice_call',
    peerId
  });

  const roomRow = await kvGet(`room:${roomRes.roomId}`);
  const voiceRoom = payload(roomRow);

  if (roomRow) {
    voiceRoom.invitedPlayerId = toFriendId;
    voiceRoom.updatedAt = now();

    await kvPut({
      pk: `room:${roomRes.roomId}`,
      type: 'room',
      owner: playerId,
      expiresAt: voiceRoom.reconnectUntil || now() + CFG.roomTtlMs,
      data: voiceRoom
    });
  }

  const callId = rid('voice');
  await saveVoiceLog({
    callId,
    fromPlayerId: playerId,
    toPlayerId: toFriendId,
    roomId: roomRes.roomId,
    status: 'ringing'
  });

  await kvPut({
    pk: `push:${toFriendId}:${now().toString().padStart(13, '0')}_${callId}`,
    type: 'push',
    owner: toFriendId,
    expiresAt: now() + 2 * 60 * 1000,
    data: {
      pushId: callId,
      callId,
      fromFriendId: playerId,
      kind: 'VOICE_CALL',
      roomId: roomRes.roomId,
      roomSecret: roomRes.roomSecret,
      createdAt: now(),
      expiresAt: now() + 2 * 60 * 1000
    }
  }).catch(() => null);

  const profile = payload(await kvGet(`profile:${playerId}`));
  const fromName = safe(profile.displayName || body.displayName || 'Друг').slice(0, 80);

  const webPush = await sendSystemWebPush({
    toPlayerId: toFriendId,
    title: `📞 ${fromName}`,
    body: 'Входящий звонок',
    url: './?openFriends=1',
    tag: `voice-${roomRes.roomId}`,
    requireInteraction: true,
    kind: 'VOICE_CALL',
    fromFriendId: playerId,
    callId
  });

  return {
    ok: true,
    callId,
    roomId: roomRes.roomId,
    roomSecret: roomRes.roomSecret,
    hostPeerId: roomRes.hostPeerId,
    guestPeerId: roomRes.guestPeerId,
    webPush
  };
}

async function actionVoiceCallJoin(event, body) {
  const {
    playerId,
    friendId,
    room: voiceRoomKey
  } = await requireFriendContext(event, body, {
    friendFields: ['friendId', 'fromFriendId']
  });

  const callId = sanitizeId(body.callId || '', 96);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret || body.secret || body.key || '');
  const peerId = sanitizeId(
    body.peerId || `${playerId}:voice:${rid('p')}`,
    140
  );

  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);

  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }
  if (room.gameId !== 'voice_call' || room.hostPlayerId !== friendId) {
    return { ok: false, reason: 'voice_room_forbidden' };
  }
  if (room.invitedPlayerId !== playerId) {
    return { ok: false, reason: 'room_invite_forbidden' };
  }

  if (callId) {
    const logRow = await kvGet(`voice:${voiceRoomKey}:${callId}`);
    const log = payload(logRow);

    if (!logRow) return { ok: false, reason: 'voice_call_not_found' };
    if (
      log.fromPlayerId !== friendId ||
      log.toPlayerId !== playerId ||
      log.roomId !== roomId
    ) {
      return { ok: false, reason: 'voice_call_forbidden' };
    }
    if (log.status === 'connected') {
      return { ok: false, reason: 'voice_busy' };
    }
  }

  const joined = await actionRoomJoin(event, {
    ...body,
    roomId,
    roomSecret,
    peerId
  });

  if (!joined?.ok) return joined;

  if (callId) {
    await saveVoiceLog({
      callId,
      fromPlayerId: friendId,
      toPlayerId: playerId,
      roomId,
      status: 'connected',
      startedAt: now()
    });
  }

  return {
    ok: true,
    callId,
    roomId,
    roomSecret,
    hostPeerId: joined.hostPeerId,
    guestPeerId: joined.guestPeerId,
    room: joined.room
  };
}

async function actionVoiceCallEnd(event, body) {
  const {
    playerId,
    friendId,
    room: voiceRoomKey
  } = await requireFriendContext(event, body, {
    friendFields: ['friendId', 'withFriendId']
  });

  const callId = sanitizeId(body.callId || '', 96);
  const roomId = sanitizeId(body.roomId);
  const status = sanitizeId(body.status || 'ended', 40);
  const durationSec = Math.max(0, Math.min(num(body.durationSec), 86400));

  if (roomId) {
    await actionRoomClose(event, {
      ...body,
      roomId
    }).catch(() => null);
  }

  if (!callId) return { ok: true, ended: false };

  const logRow = await kvGet(`voice:${voiceRoomKey}:${callId}`);
  const log = payload(logRow);

  if (!logRow) return { ok: true, ended: false };

  const participants = new Set([
    safe(log.fromPlayerId),
    safe(log.toPlayerId)
  ]);

  if (!participants.has(playerId) || !participants.has(friendId)) {
    throw new Error('voice_call_forbidden');
  }
  if (roomId && log.roomId && log.roomId !== roomId) {
    throw new Error('voice_room_mismatch');
  }

  await saveVoiceLog({
    callId,
    fromPlayerId: log.fromPlayerId,
    toPlayerId: log.toPlayerId,
    roomId: log.roomId || roomId,
    status,
    startedAt: num(log.startedAt),
    endedAt: now(),
    durationSec
  });

  return { ok: true, ended: true };
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
  return {
    ok: true,
    version: 1,
    legacyFrozen: true,
    leaders
  };
}

async function actionRtcConfig(event, body) {
  const { playerId } = await requirePlayer(event, body);

  const iceServers = [
    { urls: 'stun:stun.sipnet.ru:3478' },
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' }
  ];

  const temporaryTurn = !CFG.turnDisabled &&
    CFG.turnUrls.length &&
    CFG.turnSharedSecret;

  const staticTurn = !CFG.turnDisabled &&
    CFG.turnUrls.length &&
    CFG.turnUsername &&
    CFG.turnCredential;

  if (temporaryTurn) {
    const expires = Math.floor(Date.now() / 1000) + CFG.turnCredentialTtlSec;
    const username = `${expires}:${playerId}`;
    const credential = crypto
      .createHmac('sha1', CFG.turnSharedSecret)
      .update(username)
      .digest('base64');

    iceServers.unshift({
      urls: CFG.turnUrls,
      username,
      credential
    });
  } else if (staticTurn) {
    iceServers.unshift({
      urls: CFG.turnUrls,
      username: CFG.turnUsername,
      credential: CFG.turnCredential
    });
  }

  const hasTurn = !!(temporaryTurn || staticTurn);

  return {
    ok: true,
    iceServers,
    hasTurn,
    temporaryCredentials: !!temporaryTurn,
    expiresInSec: temporaryTurn ? CFG.turnCredentialTtlSec : 0,
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
  const { playerId } = await requirePlayer(event, body);
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
  const { playerId } = await requirePlayer(event, body);
  const endpoint = safe(body.endpoint || body.subscription?.endpoint || '');
  if (!endpoint) return { ok: true, removed: false };

  await kvDelete(`webPushSub:${playerId}:${hash(endpoint).slice(0, 32)}`).catch(() => null);
  return { ok: true, removed: true };
}

function nearbyCode() {
  return String(crypto.randomInt(100000, 999999));
}

async function actionNearbyFriendCreate(event, body) {
  const { playerId } = await requirePlayer(event, body);
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
  await requirePlayer(event, body);
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
  const { playerId } = await requirePlayer(event, body);
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
  await requirePlayer(event, body);
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
  const { playerId } = await requirePlayer(event, body);
  const code = safe(body.code || '').replace(/\D/g, '').slice(0, 6);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret);

  if (!code || code.length < 4) throw new Error('lan_code_required');
  if (!roomId || !roomSecret) throw new Error('room_data_required');

  const row = await kvGet(`room:${roomId}`);
  const room = payload(row);
  if (!row || room.roomSecretHash !== hash(roomSecret)) return { ok: false, reason: 'room_not_found' };
  if (room.hostPlayerId !== playerId) return { ok: false, reason: 'room_owner_forbidden' };

  room.ranked = !!body.ranked;
  // localOnly больше не форсируем: гость не должен получать урезанный ICE.
  // LAN-режим — это просто способ обмена кодом, а не запрет STUN.
  room.localOnly = false;
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
await requirePlayer(event, body);
const code = safe(body.code || '').replace(/\D/g, '').slice(0, 6);
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
  localOnly: false,
  matchMode: data.ranked ? 'ranked' : 'casual',
  hostPlayerId: data.hostPlayerId,
  expiresAt: data.expiresAt
};
}
const ACTIONS = {
  social_session_issue: actionSocialSessionIssue,
  player_register: actionPlayerRegister,
  presence_heartbeat: actionHeartbeat,
  friend_status_check: actionFriendStatus,
  friend_invite_create: actionFriendInviteCreate,
  friend_invite_get: actionFriendInviteGet,
  friend_invite_accept: actionFriendInviteAccept,
  room_create: actionRoomCreate,
  room_join: actionRoomJoin,
  room_get: actionRoomGet,
  room_close: actionRoomClose,
  room_set_mode: actionRoomSetMode,
  signal_send: actionSignalSend,
  signal_poll: actionSignalPoll,
  game_invite_create: actionGameInviteCreate,
  game_invite_poll: actionGameInvitePoll,
  game_invite_accept: (e, b) => actionGameInviteSet(e, b, 'accepted'),
  game_invite_reject: (e, b) => actionGameInviteSet(e, b, 'rejected'),
  game_invite_cancel: (e, b) => actionGameInviteSet(e, b, 'cancelled'),
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
  push_ack: actionPushAck,
  signal_ack: actionSignalAck,
  crypto_device_register: actionCryptoDeviceRegister,
  crypto_device_list: actionCryptoDeviceList,
  crypto_device_self_list: actionCryptoDeviceSelfList,
  crypto_device_revoke: actionCryptoDeviceRevoke,
  crypto_device_reset: actionCryptoDeviceReset,
  chat_settings_get: actionChatSettingsGet,
  chat_settings_set: actionChatSettingsSet,
  chat_purge_both: actionChatPurgeBoth,

  // ===== FRIENDS / E2EE V2 =====
  profile_set: actionProfileSet,
  profile_get: actionProfileGet,
  friend_list: actionFriendList,
  friend_remove: actionFriendRemove,
  presence_batch: actionPresenceBatch,
  push_send: actionPushSend,
  push_poll: actionPushPoll,
  chat_send_v2: actionChatSendV2,
  chat_update_v2: actionChatUpdateV2,
  chat_delete_v2: actionChatDeleteV2,
  chat_poll: actionChatPoll,
  chat_message_get: actionChatMessageGet,
  chat_clear: actionChatClear,
  chat_delivery: actionChatDelivered,
  chat_read: actionChatRead,
  voice_history: actionVoiceHistory,
  voice_call_create: actionVoiceCallCreate,
  voice_call_join: actionVoiceCallJoin,
  voice_call_end: actionVoiceCallEnd
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
        socialSessionConfigured: !!CFG.socialSessionSecret,
        authMode: 'signed-social-session-only',
        chatE2eeV2: CFG.chatE2eeV2,
        chatMode: 'e2ee-v2-only',
        temporaryTurnConfigured: !!CFG.turnSharedSecret,
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
    const msg = safe(e?.message || 'server_error');
    let status = num(e?.httpStatus);

    if (!status) {
      if (
        /RESOURCE_EXHAUSTED|resource_exhausted|Too many|overload|rate_limit/i.test(msg)
      ) {
        status = 429;
      } else if (
        /social_session|yandex_oauth/i.test(msg)
      ) {
        status = 401;
      } else if (
        /forbidden|identity_mismatch/i.test(msg)
      ) {
        status = 403;
      } else if (
        /chat_revision_conflict|crypto_.*(?:missing|not_ready|conflict)|chat_e2ee_disabled/i.test(msg)
      ) {
        status = 409;
      } else if (
        /required|bad_|not_found/i.test(msg)
      ) {
        status = 400;
      } else {
        status = 500;
      }
    }

    console.error('[vi3-signaling]', {
      action,
      status,
      error: msg
    });

    return reply(event, status, {
      ok: false,
      error: msg
    });
  }
};
