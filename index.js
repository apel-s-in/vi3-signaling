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
  roomJoinTokenTtlMs: Math.max(
    30000,
    Math.min(
      num(process.env.ROOM_JOIN_TOKEN_TTL_MS, 120000),
      10 * 60 * 1000
    )
  ),
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
  listeningReceiptsShadow:
    safe(process.env.LISTENING_RECEIPTS_SHADOW || '1') === '1',
  favoriteRewardsShadow:
    safe(process.env.FAVORITE_REWARDS_SHADOW || '1') === '1',
  backupRewardsShadow:
    safe(process.env.BACKUP_REWARDS_SHADOW || '1') === '1',
  backupReceiptSecret:
    safe(process.env.BACKUP_RECEIPT_SECRET || ''),
  listenHeartbeatMinMs: Math.max(
    5000,
    Math.min(
      num(process.env.LISTEN_HEARTBEAT_MIN_MS, 8000),
      30000
    )
  ),
  listenHeartbeatMaxGapMs: Math.max(
    30000,
    Math.min(
      num(process.env.LISTEN_HEARTBEAT_MAX_GAP_MS, 90000),
      180000
    )
  ),
  listenBackgroundMaxGapMs: Math.max(
    180000,
    Math.min(
      num(process.env.LISTEN_BACKGROUND_MAX_GAP_MS, 900000),
      1800000
    )
  ),
  listenSessionMaxMs: Math.max(
    10 * 60 * 1000,
    Math.min(
      num(process.env.LISTEN_SESSION_MAX_MS, 8 * 60 * 60 * 1000),
      24 * 60 * 60 * 1000
    )
  ),
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

function sortObject(value) {
  if (Array.isArray(value)) {
    return value.map(sortObject);
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  return Object.keys(value)
    .sort()
    .reduce((out, key) => {
      out[key] = sortObject(value[key]);
      return out;
    }, {});
}

function stableStringify(value) {
  return JSON.stringify(sortObject(value));
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

function parseListenTrackCatalog(raw) {
  let parsed;

  try {
    parsed = JSON.parse(String(raw || '{}'));
  } catch {
    parsed = {};
  }

  const rows = Array.isArray(parsed)
    ? parsed
    : Object.entries(
        parsed && typeof parsed === 'object'
          ? parsed
          : {}
      ).map(([uid, value]) => {
        if (Array.isArray(value)) {
          return {
            uid,
            duration: value[0],
            album: value[1]
          };
        }

        return {
          uid,
          ...(value && typeof value === 'object'
            ? value
            : { duration: value })
        };
      });

  return new Map(
    rows
      .map(item => {
        const uid = sanitizeId(item?.uid, 160);
        const rawDuration = Number(item?.duration);
        const album = sanitizeId(item?.album, 120);

        if (
          !uid ||
          !album ||
          !Number.isFinite(rawDuration) ||
          rawDuration < 10 ||
          rawDuration > 7200
        ) {
          return null;
        }

        return [
          uid,
          Object.freeze({
            uid,
            duration: Math.round(rawDuration * 1000) / 1000,
            album
          })
        ];
      })
      .filter(Boolean)
  );
}

const LISTEN_TRACK_CATALOG = parseListenTrackCatalog(
  process.env.LISTEN_TRACK_CATALOG_JSON
);

const LISTEN_ALBUM_TRACKS = new Map();

for (const track of LISTEN_TRACK_CATALOG.values()) {
  if (!LISTEN_ALBUM_TRACKS.has(track.album)) {
    LISTEN_ALBUM_TRACKS.set(track.album, []);
  }

  LISTEN_ALBUM_TRACKS.get(track.album).push(track.uid);
}

const buildScaledRewards = ({
  id,
  metric,
  targets,
  xpBase,
  xpMultiplier,
  channel = 'listening'
}) => targets.map((target, index) => ({
  id: `${id}_${index + 1}`,
  metric,
  channel,
  target,
  amount: Math.floor(
    xpBase * Math.pow(xpMultiplier, index)
  ),
  validatorVersion: 1
}));

const ACHIEVEMENT_REWARD_CATALOG = Object.freeze([
  ...buildScaledRewards({
    id: 'play_total',
    metric: 'validPlays',
    targets: [1, 25, 100, 500, 1000, 5000],
    xpBase: 10,
    xpMultiplier: 1.5
  }),
  ...buildScaledRewards({
    id: 'full_total',
    metric: 'fullPlays',
    targets: [1, 10, 50, 100, 500, 1000],
    xpBase: 15,
    xpMultiplier: 1.8
  }),
  ...buildScaledRewards({
    id: 'time_total',
    metric: 'totalSec',
    targets: [3600, 18000, 36000, 86400, 360000],
    xpBase: 25,
    xpMultiplier: 2
  }),
  ...buildScaledRewards({
    id: 'streak_base',
    metric: 'streak',
    targets: [3, 7, 14, 30, 100, 365],
    xpBase: 30,
    xpMultiplier: 1.8
  }),
  ...buildScaledRewards({
    id: 'unique_tracks',
    metric: 'uniqueTracks',
    targets: [5, 10, 16, 50, 100],
    xpBase: 20,
    xpMultiplier: 1.5
  }),
  ...buildScaledRewards({
    id: 'one_track_full',
    metric: 'maxOneTrackFull',
    targets: [10, 25, 100, 500],
    xpBase: 50,
    xpMultiplier: 2
  }),
  ...buildScaledRewards({
    id: 'fav_total',
    metric: 'favCount',
    channel: 'favorite',
    targets: [3, 5, 8, 15, 50],
    xpBase: 10,
    xpMultiplier: 1.4
  }),
  ...buildScaledRewards({
    id: 'backup_saves',
    metric: 'backupSaves',
    channel: 'backup',
    targets: [1, 3, 10],
    xpBase: 20,
    xpMultiplier: 1.5
  }),
  ...[...LISTEN_ALBUM_TRACKS.keys()].map(album => ({
    id: `album_complete_${album}`,
    metric: 'albumComplete',
    channel: 'listening',
    album,
    target: 1,
    amount: 150,
    validatorVersion: 1
  }))
]);

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
  const sets = Array.isArray(res?.resultSets)
    ? res.resultSets
    : res?.resultSet
      ? [res.resultSet]
      : [];

  const rs =
    sets.find(set =>
      Array.isArray(set?.rows) &&
      set.rows.length > 0
    ) ||
    sets.find(set =>
      Array.isArray(set?.columns) &&
      set.columns.length > 0
    ) ||
    null;

  const rows = rs?.rows || [];
  const cols = (rs?.columns || [])
    .map(column => safe(column.name || column));

  return rows.map(row => {
    const items = row.items || row;
    if (!Array.isArray(items)) return row;

    const out = {};

    items.forEach((item, index) => {
      out[cols[index] || `c${index}`] = valueOf(item);
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

async function kvInsert({
  pk,
  type = '',
  owner = '',
  expiresAt = 0,
  data = {}
}) {
  await query(`
    DECLARE $pk AS Utf8;
    DECLARE $type AS Utf8;
    DECLARE $owner AS Utf8;
    DECLARE $updated_at AS Uint64;
    DECLARE $expires_at AS Uint64;
    DECLARE $payload_json AS Utf8;

    INSERT INTO ${TABLE} (
      pk,
      type,
      owner,
      updated_at,
      expires_at,
      payload_json
    )
    VALUES (
      $pk,
      $type,
      $owner,
      $updated_at,
      $expires_at,
      $payload_json
    );
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

  const expectedPayloadJson = safe(row.payload_json);
  if (!expectedPayloadJson) {
    throw new Error('cas_payload_required');
  }

  const nextUpdatedAt = Math.max(
    now(),
    num(row.updated_at) + 1
  );
  const casToken = rid('cas');
  const storedData = {
    ...(data || {}),
    __casToken: casToken
  };

  await query(`
    DECLARE $pk AS Utf8;
    DECLARE $expected_payload_json AS Utf8;
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
      AND payload_json = $expected_payload_json;
  `, {
    '$pk': tvUtf8(row.pk),
    '$expected_payload_json': tvUtf8(expectedPayloadJson),
    '$type': tvUtf8(type),
    '$owner': tvUtf8(owner),
    '$next_updated_at': tvUint64(nextUpdatedAt),
    '$expires_at': tvUint64(expiresAt),
    '$payload_json': tvUtf8(JSON.stringify(storedData))
  });

  const verified = await kvGet(row.pk);
  return payload(verified)?.__casToken === casToken;
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

  const registrationGrant =
    await ensureRegistrationShardGrant(
      identity.friendId
    ).catch(error => ({
      ok: false,
      duplicate: false,
      amount: 0,
      operationId: '',
      error: safe(error?.message)
    }));

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
    registrationGrant: {
      ok: registrationGrant.ok === true,
      amount: num(registrationGrant.amount),
      duplicate: registrationGrant.duplicate === true,
      operationId: safe(
        registrationGrant.operationId
      ),
      error: safe(registrationGrant.error)
    },
    wallet: registrationGrant.wallet
      ? publicShardWallet(registrationGrant.wallet)
      : null,
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

function roomJoinTokenKey(token) {
  const value = safe(token);
  return value
    ? `roomJoinToken:${hash(value)}`
    : '';
}

async function getRoomJoinToken(token) {
  const pk = roomJoinTokenKey(token);
  if (!pk) return { row: null, data: {} };

  const row = await kvGet(pk);
  return {
    row,
    data: payload(row)
  };
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

async function actionRoomJoinTokenCreate(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(
    body.roomSecret ||
    body.secret ||
    body.key ||
    ''
  );

  const roomRow = roomId
    ? await kvGet(`room:${roomId}`)
    : null;
  const room = payload(roomRow);

  if (
    !roomRow ||
    room.roomSecretHash !== hash(roomSecret)
  ) {
    return {
      ok: false,
      reason: 'room_not_found'
    };
  }

  if (room.hostPlayerId !== playerId) {
    return {
      ok: false,
      reason: 'room_host_required'
    };
  }

  if (
    room.status === 'closed' ||
    num(room.closedAt) > 0
  ) {
    return {
      ok: false,
      reason: 'room_closed'
    };
  }

  await enforceRateLimit({
    scope: 'room_join_token',
    actor: playerId,
    limit: 30,
    windowMs: 10 * 60 * 1000
  });

  const token = base64url(crypto.randomBytes(24));
  const createdAt = now();
  const expiresAt = Math.min(
    num(room.reconnectUntil) ||
      createdAt + CFG.roomTtlMs,
    createdAt + CFG.roomJoinTokenTtlMs
  );
  const invitedPlayerId = sanitizeId(
    body.invitedPlayerId ||
    body.toFriendId ||
    ''
  );

  const data = {
    roomId,
    roomSecret,
    gameId: sanitizeId(room.gameId || 'game', 80),
    createdByPlayerId: playerId,
    invitedPlayerId,
    createdAt,
    expiresAt,
    redeemedAt: 0,
    redeemedByPlayerId: ''
  };

  await kvPut({
    pk: roomJoinTokenKey(token),
    type: 'roomJoinToken',
    owner: playerId,
    expiresAt,
    data
  });

  return {
    ok: true,
    token,
    gameId: data.gameId,
    expiresAt
  };
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

async function actionRoomJoinTokenRedeem(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const token = safe(
    body.joinToken ||
    body.token ||
    ''
  );

  if (!token || token.length > 180) {
    throw new Error('room_join_token_required');
  }

  const { row, data } = await getRoomJoinToken(token);

  if (!row || !data.roomId || !data.roomSecret) {
    return {
      ok: false,
      reason: 'room_join_token_not_found'
    };
  }

  if (
    num(data.expiresAt) > 0 &&
    num(data.expiresAt) < now()
  ) {
    return {
      ok: false,
      reason: 'room_join_token_expired'
    };
  }

  if (
    data.invitedPlayerId &&
    data.invitedPlayerId !== playerId
  ) {
    return {
      ok: false,
      reason: 'room_join_token_forbidden'
    };
  }

  if (
    num(data.redeemedAt) > 0 ||
    data.redeemedByPlayerId
  ) {
    return {
      ok: false,
      reason: 'room_join_token_used'
    };
  }

  const updated = {
    ...data,
    redeemedAt: now(),
    redeemedByPlayerId: playerId
  };

  const changed = await kvCompareAndPut({
    row,
    type: 'roomJoinToken',
    owner: data.createdByPlayerId || '',
    expiresAt: num(data.expiresAt),
    data: updated
  });

  if (!changed) {
    return {
      ok: false,
      reason: 'room_join_token_used'
    };
  }

  return {
    ok: true,
    roomId: data.roomId,
    roomSecret: data.roomSecret,
    gameId: data.gameId,
    expiresAt: num(data.expiresAt)
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

// ===== FRIENDS / E2EE V2 =====

async function actionProfileSet(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const old = payload(
    await kvGet(`profile:${playerId}`)
  );

  const profile = {
    ...old,
    friendId: playerId,
    displayName: safe(
      body.displayName ||
      old.displayName ||
      'Слушатель'
    ).slice(0, 80),
    avatarUrl: safe(
      body.avatarUrl ||
      old.avatarUrl ||
      ''
    ).slice(0, 400),
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
  let gameId = sanitizeId(body.gameId || '');
  const joinToken = safe(body.joinToken || '').slice(0, 180);
  const text = safe(body.text || '').slice(0, 300);

  let gameRoomId = '';

  if (kind === 'GAME_INVITE') {
    const join = await getRoomJoinToken(joinToken);

    const tokenGameId = sanitizeId(
      join.data.gameId || ''
    );

    if (
      !join.row ||
      join.data.createdByPlayerId !== playerId ||
      num(join.data.redeemedAt) > 0 ||
      join.data.redeemedByPlayerId ||
      !tokenGameId ||
      (gameId && gameId !== tokenGameId) ||
      (
        join.data.invitedPlayerId &&
        join.data.invitedPlayerId !== toFriendId
      )
    ) {
      throw new Error('game_join_token_invalid');
    }

    gameId = tokenGameId;
    gameRoomId = sanitizeId(join.data.roomId);
  }
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
      joinToken,
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
    tag: isGameInvite
      ? `game-${gameRoomId || pushId}`
      : `push-${pushId}`,
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
const FAVORITE_STATE_VERSION = 1;
const FAVORITE_MUTATION_HISTORY_LIMIT = 500;

function favoriteStateKey(playerId) {
  return `favoriteState:${sanitizeId(playerId, 96)}`;
}

function normalizeFavoriteItem(uid, raw = {}) {
  const trackUid = sanitizeId(uid || raw.uid, 160);
  const track = LISTEN_TRACK_CATALOG.get(trackUid);

  if (!track) return null;

  const status = ['active', 'inactive', 'deleted']
    .includes(safe(raw.status))
    ? safe(raw.status)
    : raw.deletedAt
      ? 'deleted'
      : raw.inactiveAt
        ? 'inactive'
        : 'active';

  return {
    uid: trackUid,
    album: track.album,
    status,
    liked: status === 'active',
    addedAt: Math.max(0, num(raw.addedAt)),
    updatedAt: Math.max(0, num(raw.updatedAt)),
    inactiveAt: status === 'inactive'
      ? Math.max(0, num(raw.inactiveAt || raw.updatedAt))
      : 0,
    deletedAt: status === 'deleted'
      ? Math.max(0, num(raw.deletedAt || raw.updatedAt))
      : 0,
    rewardEligible: raw.rewardEligible === true,
    mutationId: sanitizeId(raw.mutationId, 160)
  };
}

function normalizeFavoriteState(raw = {}, playerId = '') {
  const sourceItems =
    raw.items && typeof raw.items === 'object'
      ? raw.items
      : {};

  const items = {};

  Object.entries(sourceItems).forEach(([uid, item]) => {
    const normalized = normalizeFavoriteItem(uid, item);
    if (normalized) items[normalized.uid] = normalized;
  });

  return {
    version: FAVORITE_STATE_VERSION,
    playerId: sanitizeId(
      playerId || raw.playerId,
      96
    ),
    revision: Math.max(
      0,
      Math.floor(num(raw.revision))
    ),
    items,
    mutationIds: [...new Set(
      (Array.isArray(raw.mutationIds)
        ? raw.mutationIds
        : [])
        .map(value => sanitizeId(value, 160))
        .filter(Boolean)
    )].slice(-FAVORITE_MUTATION_HISTORY_LIMIT),
    bootstrapImportedAt: Math.max(
      0,
      num(raw.bootstrapImportedAt)
    ),
    createdAt: Math.max(
      0,
      num(raw.createdAt)
    ) || now(),
    updatedAt: Math.max(
      0,
      num(raw.updatedAt)
    ) || now()
  };
}

function publicFavoriteState(raw) {
  const state = normalizeFavoriteState(
    raw,
    raw?.playerId
  );

  const items = Object.values(state.items)
    .sort((left, right) =>
      num(left.addedAt) - num(right.addedAt) ||
      left.uid.localeCompare(right.uid)
    );

  return {
    version: state.version,
    revision: state.revision,
    activeCount: items.filter(
      item => item.status === 'active'
    ).length,
    rewardEligibleCount: items.filter(
      item =>
        item.status === 'active' &&
        item.rewardEligible
    ).length,
    items: items.map(item => ({
      uid: item.uid,
      album: item.album,
      status: item.status,
      liked: item.status === 'active',
      addedAt: item.addedAt,
      updatedAt: item.updatedAt,
      inactiveAt: item.inactiveAt,
      deletedAt: item.deletedAt
    })),
    bootstrapImported:
      state.bootstrapImportedAt > 0,
    bootstrapImportedAt:
      state.bootstrapImportedAt,
    updatedAt: state.updatedAt
  };
}

async function getOrCreateFavoriteState(playerId) {
  const key = favoriteStateKey(playerId);
  let row = await kvGet(key);

  if (!row) {
    const state = normalizeFavoriteState(
      {},
      playerId
    );

    try {
      await kvInsert({
        pk: key,
        type: 'favoriteState',
        owner: playerId,
        data: state
      });
    } catch {}

    row = await kvGet(key);
  }

  if (!row) {
    throw new Error('favorite_state_create_failed');
  }

  return {
    row,
    state: normalizeFavoriteState(
      payload(row),
      playerId
    )
  };
}

function favoriteRewardCount(raw) {
  const state = normalizeFavoriteState(
    raw,
    raw?.playerId
  );

  return Object.values(state.items)
    .filter(item =>
      item.status === 'active' &&
      item.rewardEligible
    )
    .length;
}

async function actionFavoriteStateGet(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const { state } =
    await getOrCreateFavoriteState(playerId);

  const progress = normalizeAchievementProgress(
    payload(await kvGet(
      achievementProgressKey(playerId)
    )),
    playerId
  );

  const rewards = await reconcileAchievementRewards(
    playerId,
    progress
  );

  return {
    ok: true,
    shadow: CFG.favoriteRewardsShadow,
    rewardsEnabled:
      !CFG.favoriteRewardsShadow,
    state: publicFavoriteState(state),
    rewards: rewards.grants,
    wallet: rewards.wallet
      ? publicShardWallet(rewards.wallet)
      : null
  };
}

async function actionFavoriteStateMutate(event, body) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'favorite_mutate',
    actor: playerId,
    limit: 180,
    windowMs: 60 * 60 * 1000
  });

  const uid = sanitizeId(body.uid, 160);
  const track = LISTEN_TRACK_CATALOG.get(uid);
  const mutationId = sanitizeId(
    body.mutationId,
    160
  );
  const requestedStatus = sanitizeId(
    body.status,
    20
  );

  if (!track) {
    throw new Error('favorite_track_not_catalogued');
  }

  if (!mutationId) {
    throw new Error('favorite_mutation_id_required');
  }

  if (
    !['active', 'inactive', 'deleted']
      .includes(requestedStatus)
  ) {
    throw new Error('favorite_status_invalid');
  }

  for (let attempt = 0; attempt < 10; attempt++) {
    const { row, state } =
      await getOrCreateFavoriteState(playerId);

    if (state.mutationIds.includes(mutationId)) {
      return {
        ok: true,
        duplicate: true,
        shadow: CFG.favoriteRewardsShadow,
        state: publicFavoriteState(state),
        rewards: []
      };
    }

    const at = now();
    const old = state.items[uid] || null;

    const item = normalizeFavoriteItem(uid, {
      ...old,
      uid,
      album: track.album,
      status: requestedStatus,
      addedAt:
        old?.addedAt ||
        at,
      updatedAt: at,
      inactiveAt:
        requestedStatus === 'inactive'
          ? at
          : 0,
      deletedAt:
        requestedStatus === 'deleted'
          ? at
          : 0,
      rewardEligible:
        requestedStatus === 'active'
          ? true
          : old?.rewardEligible === true,
      mutationId
    });

    const next = normalizeFavoriteState({
      ...state,
      revision: state.revision + 1,
      items: {
        ...state.items,
        [uid]: item
      },
      mutationIds: [
        ...state.mutationIds,
        mutationId
      ],
      updatedAt: at
    }, playerId);

    if (!await kvCompareAndPut({
      row,
      type: 'favoriteState',
      owner: playerId,
      data: next
    })) {
      continue;
    }

    const progress = normalizeAchievementProgress(
      payload(await kvGet(
        achievementProgressKey(playerId)
      )),
      playerId
    );

    const rewards =
      await reconcileAchievementRewards(
        playerId,
        progress
      );

    return {
      ok: true,
      duplicate: false,
      shadow: CFG.favoriteRewardsShadow,
      rewardsEnabled:
        !CFG.favoriteRewardsShadow,
      mutationId,
      item,
      state: publicFavoriteState(next),
      rewards: rewards.grants,
      wallet: rewards.wallet
        ? publicShardWallet(rewards.wallet)
        : null
    };
  }

  throw new Error('favorite_state_conflict');
}

async function actionFavoriteStateReconcile(
  event,
  body
) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'favorite_reconcile',
    actor: playerId,
    limit: 20,
    windowMs: 60 * 60 * 1000
  });

  for (let attempt = 0; attempt < 10; attempt++) {
    const { row, state } =
      await getOrCreateFavoriteState(playerId);

    if (
      state.revision > 0 ||
      Object.keys(state.items).length > 0
    ) {
      return {
        ok: true,
        imported: false,
        reason: 'server_state_exists',
        shadow: CFG.favoriteRewardsShadow,
        state: publicFavoriteState(state)
      };
    }

    const input = Array.isArray(body.items)
      ? body.items.slice(
          0,
          LISTEN_TRACK_CATALOG.size
        )
      : [];

    const items = {};
    const at = now();

    input.forEach(raw => {
      const uid = sanitizeId(raw?.uid, 160);
      const track = LISTEN_TRACK_CATALOG.get(uid);

      if (!track) return;

      const status = ['active', 'inactive', 'deleted']
        .includes(safe(raw?.status))
        ? safe(raw.status)
        : raw?.deletedAt
          ? 'deleted'
          : raw?.inactiveAt
            ? 'inactive'
            : 'active';

      const item = normalizeFavoriteItem(uid, {
        uid,
        album: track.album,
        status,
        addedAt: Math.max(
          0,
          num(raw?.addedAt)
        ) || at,
        updatedAt: at,
        inactiveAt:
          status === 'inactive'
            ? at
            : 0,
        deletedAt:
          status === 'deleted'
            ? at
            : 0,
        rewardEligible: false,
        mutationId: ''
      });

      if (item) items[uid] = item;
    });

    const next = normalizeFavoriteState({
      ...state,
      revision: Object.keys(items).length
        ? 1
        : 0,
      items,
      bootstrapImportedAt:
        Object.keys(items).length
          ? at
          : 0,
      updatedAt: at
    }, playerId);

    if (!await kvCompareAndPut({
      row,
      type: 'favoriteState',
      owner: playerId,
      data: next
    })) {
      continue;
    }

    return {
      ok: true,
      imported: Object.keys(items).length > 0,
      reason: Object.keys(items).length
        ? 'legacy_local_bootstrap'
        : 'empty_local_state',
      shadow: CFG.favoriteRewardsShadow,
      state: publicFavoriteState(next)
    };
  }

  throw new Error('favorite_reconcile_conflict');
}

const LISTEN_RECEIPT_VERSION = 1;
const LISTEN_SESSION_RETENTION_MS =
  90 * 24 * 60 * 60 * 1000;
const LISTEN_PROGRESS_RECEIPT_LIMIT = 5000;

function listenActiveKey(playerId, deviceId = '') {
  const base =
    `listenActive:${sanitizeId(playerId, 96)}`;
  const device = sanitizeId(deviceId, 120);

  return device
    ? `${base}:${device}`
    : base;
}

function listenSessionKey(playerId, sessionId) {
  return [
    'listen',
    sanitizeId(playerId, 96),
    sanitizeId(sessionId, 120)
  ].join(':');
}

async function resolveListenSessionRow(
  playerId,
  sessionId
) {
  const historyKey = listenSessionKey(
    playerId,
    sessionId
  );
  const historyRow = await kvGet(historyKey);
  const history = normalizeListenSession(
    payload(historyRow)
  );

  if (
    historyRow &&
    history.playerId === playerId &&
    history.sessionId === sessionId &&
    history.deviceId
  ) {
    const activeKey = listenActiveKey(
      playerId,
      history.deviceId
    );
    const activeRow = await kvGet(activeKey);
    const active = normalizeListenSession(
      payload(activeRow)
    );

    if (
      activeRow &&
      active.playerId === playerId &&
      active.sessionId === sessionId
    ) {
      return {
        row: activeRow,
        key: activeKey,
        session: active,
        active: true
      };
    }
  }

  // Совместимость с сессиями, созданными до per-device migration.
  const legacyKey = listenActiveKey(playerId);
  const legacyRow = await kvGet(legacyKey);
  const legacy = normalizeListenSession(
    payload(legacyRow)
  );

  if (
    legacyRow &&
    legacy.playerId === playerId &&
    legacy.sessionId === sessionId
  ) {
    return {
      row: legacyRow,
      key: legacyKey,
      session: legacy,
      active: true
    };
  }

  return {
    row: historyRow,
    key: historyKey,
    session: history,
    active: false
  };
}

function listenReceiptKey(playerId, receiptId) {
  return [
    'listenReceipt',
    sanitizeId(playerId, 96),
    sanitizeId(receiptId, 120)
  ].join(':');
}

function achievementProgressKey(playerId) {
  return `achievementProgress:${sanitizeId(playerId, 96)}`;
}

function listenTrackFromCatalog(trackUid) {
  const uid = sanitizeId(trackUid, 160);
  const track = LISTEN_TRACK_CATALOG.get(uid);

  if (!track) {
    const error = new Error('listen_track_not_catalogued');
    error.httpStatus = 409;
    throw error;
  }

  return track;
}

function normalizeListenSession(raw = {}) {
  return {
    version: LISTEN_RECEIPT_VERSION,
    playerId: sanitizeId(raw.playerId, 96),
    sessionId: sanitizeId(raw.sessionId, 120),
    deviceId: sanitizeId(raw.deviceId, 120),
    trackUid: sanitizeId(raw.trackUid, 160),
    album: sanitizeId(raw.album, 120),
    duration: Math.max(
      0,
      Math.min(7200, num(raw.duration))
    ),
    variant: sanitizeId(raw.variant || 'audio', 40),
    quality: sanitizeId(raw.quality || '', 20),
    status: sanitizeId(raw.status || 'active', 30),
    startedAt: num(raw.startedAt),
    lastHeartbeatAt: num(raw.lastHeartbeatAt),
    completedAt: num(raw.completedAt),
    lastPosition: Math.max(0, num(raw.lastPosition)),
    observedMs: Math.max(0, num(raw.observedMs)),
    acceptedHeartbeats: Math.max(
      0,
      Math.floor(num(raw.acceptedHeartbeats))
    ),
    rejectedHeartbeats: Math.max(
      0,
      Math.floor(num(raw.rejectedHeartbeats))
    ),
    lastRejectReason: sanitizeId(
      raw.lastRejectReason,
      80
    ),
    completionReason: sanitizeId(
      raw.completionReason,
      40
    ),
    receiptId: sanitizeId(raw.receiptId, 120),
    visibility: sanitizeId(raw.visibility, 20),
    platform: sanitizeId(raw.platform, 30),
    updatedAt: num(raw.updatedAt)
  };
}

function normalizeAchievementProgress(raw = {}, playerId = '') {
  const uniqueTracks =
    raw.uniqueTracks && typeof raw.uniqueTracks === 'object'
      ? raw.uniqueTracks
      : {};

  const perTrackFull =
    raw.perTrackFull && typeof raw.perTrackFull === 'object'
      ? raw.perTrackFull
      : {};

  return {
    version: 1,
    playerId: sanitizeId(
      playerId || raw.playerId,
      96
    ),
    shadow: true,
    validPlays: Math.max(
      0,
      Math.floor(num(raw.validPlays))
    ),
    fullPlays: Math.max(
      0,
      Math.floor(num(raw.fullPlays))
    ),
    totalSec: Math.max(
      0,
      Math.floor(num(raw.totalSec))
    ),
    backupSaves: Math.max(
      0,
      Math.floor(num(raw.backupSaves))
    ),
    uniqueTracks: Object.fromEntries(
      Object.entries(uniqueTracks)
        .map(([uid, at]) => [
          sanitizeId(uid, 160),
          num(at)
        ])
        .filter(([uid, at]) => uid && at > 0)
    ),
    perTrackFull: Object.fromEntries(
      Object.entries(perTrackFull)
        .map(([uid, count]) => [
          sanitizeId(uid, 160),
          Math.max(0, Math.floor(num(count)))
        ])
        .filter(([uid, count]) => uid && count > 0)
    ),
    activeDays: [...new Set(
      (Array.isArray(raw.activeDays)
        ? raw.activeDays
        : [])
        .map(value => sanitizeId(value, 20))
        .filter(value => /^\d{4}-\d{2}-\d{2}$/.test(value))
    )].sort().slice(-400),
    receiptIds: [...new Set(
      (Array.isArray(raw.receiptIds)
        ? raw.receiptIds
        : [])
        .map(value => sanitizeId(value, 120))
        .filter(Boolean)
    )].slice(-LISTEN_PROGRESS_RECEIPT_LIMIT),
    backupReceiptIds: [...new Set(
      (Array.isArray(raw.backupReceiptIds)
        ? raw.backupReceiptIds
        : [])
        .map(value => sanitizeId(value, 120))
        .filter(Boolean)
    )].slice(-1000),
    updatedAt: num(raw.updatedAt)
  };
}

function utcDayKey(timestamp) {
  return new Date(num(timestamp) || now())
    .toISOString()
    .slice(0, 10);
}

function calculateServerStreak(days = []) {
  const values = [...new Set(days)]
    .filter(value => /^\d{4}-\d{2}-\d{2}$/.test(value))
    .sort();

  if (!values.length) return 0;

  let streak = 1;

  for (let index = values.length - 1; index > 0; index--) {
    const current = Date.parse(`${values[index]}T00:00:00Z`);
    const previous = Date.parse(
      `${values[index - 1]}T00:00:00Z`
    );

    if (current - previous !== 86400000) break;
    streak++;
  }

  return streak;
}

function publicListenSession(session) {
  const data = normalizeListenSession(session);

  return {
    version: data.version,
    sessionId: data.sessionId,
    trackUid: data.trackUid,
    status: data.status,
    startedAt: data.startedAt,
    lastHeartbeatAt: data.lastHeartbeatAt,
    completedAt: data.completedAt,
    observedSec: Math.floor(data.observedMs / 1000),
    acceptedHeartbeats: data.acceptedHeartbeats,
    rejectedHeartbeats: data.rejectedHeartbeats,
    lastRejectReason: data.lastRejectReason,
    receiptId: data.receiptId
  };
}

function publicAchievementProgress(progress) {
  const data = normalizeAchievementProgress(
    progress,
    progress?.playerId
  );

  return {
    version: data.version,
    shadow: CFG.listeningReceiptsShadow,
    rewardsEnabled: !CFG.listeningReceiptsShadow,
    validPlays: data.validPlays,
    fullPlays: data.fullPlays,
    totalSec: data.totalSec,
    backupSaves: data.backupSaves,
    uniqueTracks: Object.keys(data.uniqueTracks).length,
    maxOneTrackFull: Math.max(
      0,
      ...Object.values(data.perTrackFull)
    ),
    streak: calculateServerStreak(data.activeDays),
    activeDays: data.activeDays.length,
    receipts: data.receiptIds.length,
    updatedAt: data.updatedAt
  };
}

async function persistListenSession(session) {
  const data = normalizeListenSession(session);

  await kvPut({
    pk: listenSessionKey(
      data.playerId,
      data.sessionId
    ),
    type: 'listenSession',
    owner: data.playerId,
    expiresAt: now() + LISTEN_SESSION_RETENTION_MS,
    data
  });

  return data;
}

function applyListenObservation(
  session,
  body,
  {
    completed = false,
    at = now()
  } = {}
) {
  const current = normalizeListenSession(session);
  const rawPosition = Number(body.position);

  if (!Number.isFinite(rawPosition) || rawPosition < 0) {
    throw new Error('listen_position_invalid');
  }

  const position = Math.min(
    current.duration,
    rawPosition
  );
  const gapMs = Math.max(
    0,
    at - current.lastHeartbeatAt
  );
  const positionDelta =
    position - current.lastPosition;
  const mediaDeltaMs = positionDelta * 1000;
  const visibility = sanitizeId(
    body.visibility,
    20
  );
  const background =
    visibility === 'hidden' ||
    current.visibility === 'hidden';
  const maxGapMs = background
    ? CFG.listenBackgroundMaxGapMs
    : CFG.listenHeartbeatMaxGapMs;
  const forwardToleranceMs = Math.max(
    5000,
    gapMs * 0.2
  );

  if (
    !completed &&
    gapMs < CFG.listenHeartbeatMinMs
  ) {
    return {
      changed: false,
      throttled: true,
      session: current
    };
  }

  let accepted = true;
  let rejectReason = '';

  if (gapMs <= 0) {
    accepted = false;
    rejectReason = 'clock';
  } else if (gapMs > maxGapMs) {
    accepted = false;
    rejectReason = background
      ? 'background_gap'
      : 'heartbeat_gap';
  } else if (positionDelta < -2) {
    accepted = false;
    rejectReason = 'position_rewind';
  } else if (
    mediaDeltaMs >
    gapMs + forwardToleranceMs
  ) {
    accepted = false;
    rejectReason = 'position_jump';
  }

  const creditMs = accepted
    ? Math.max(
        0,
        Math.floor(
          Math.min(
            gapMs,
            mediaDeltaMs,
            maxGapMs
          )
        )
      )
    : 0;

  return {
    changed: true,
    throttled: false,
    accepted,
    creditMs,
    session: {
      ...current,
      lastHeartbeatAt: at,
      // Подозрительный интервал не получает credit, но новая позиция
      // становится baseline. Иначе один seek навсегда отравит сессию:
      // каждый следующий heartbeat будет сравниваться со старой позицией.
      lastPosition: position,
      observedMs: current.observedMs + creditMs,
      acceptedHeartbeats:
        current.acceptedHeartbeats +
        (accepted ? 1 : 0),
      rejectedHeartbeats:
        current.rejectedHeartbeats +
        (accepted ? 0 : 1),
      lastRejectReason: accepted
        ? ''
        : rejectReason,
      visibility: sanitizeId(
        body.visibility,
        20
      ),
      platform: sanitizeId(
        body.platform,
        30
      ),
      updatedAt: at
    }
  };
}

async function applyListenReceiptProgress(receipt) {
  const key = achievementProgressKey(receipt.playerId);

  for (let attempt = 0; attempt < 10; attempt++) {
    let row = await kvGet(key);

    if (!row) {
      try {
        await kvInsert({
          pk: key,
          type: 'achievementProgress',
          owner: receipt.playerId,
          data: normalizeAchievementProgress(
            {},
            receipt.playerId
          )
        });
      } catch {}

      row = await kvGet(key);
      if (!row) continue;
    }

    const progress = normalizeAchievementProgress(
      payload(row),
      receipt.playerId
    );

    if (progress.receiptIds.includes(receipt.receiptId)) {
      return {
        duplicate: true,
        progress
      };
    }

    const uniqueTracks = {
      ...progress.uniqueTracks
    };
    const perTrackFull = {
      ...progress.perTrackFull
    };
    const activeDays = [...progress.activeDays];

    if (receipt.valid) {
      uniqueTracks[receipt.trackUid] =
        uniqueTracks[receipt.trackUid] ||
        receipt.completedAt;

      const day = utcDayKey(receipt.completedAt);
      if (!activeDays.includes(day)) activeDays.push(day);
    }

    if (receipt.full) {
      perTrackFull[receipt.trackUid] =
        Math.max(
          0,
          Math.floor(num(perTrackFull[receipt.trackUid]))
        ) + 1;
    }

    const next = normalizeAchievementProgress({
      ...progress,
      validPlays:
        progress.validPlays +
        (receipt.valid ? 1 : 0),
      fullPlays:
        progress.fullPlays +
        (receipt.full ? 1 : 0),
      totalSec:
        progress.totalSec +
        (receipt.valid ? receipt.observedSec : 0),
      uniqueTracks,
      perTrackFull,
      activeDays,
      receiptIds: [
        ...progress.receiptIds,
        receipt.receiptId
      ],
      updatedAt: now()
    }, receipt.playerId);

    if (!await kvCompareAndPut({
      row,
      type: 'achievementProgress',
      owner: receipt.playerId,
      data: next
    })) {
      continue;
    }

    return {
      duplicate: false,
      progress: next
    };
  }

  throw new Error('achievement_progress_conflict');
}

async function finalizeListenSession(session) {
  const data = normalizeListenSession(session);
  const receiptId =
    data.receiptId ||
    `lr_${hash([
      data.playerId,
      data.sessionId,
      data.completedAt
    ].join(':')).slice(0, 28)}`;

  const observedSec = Math.max(
    0,
    Math.floor(data.observedMs / 1000)
  );
  const progressRatio = data.duration > 0
    ? data.lastPosition / data.duration
    : 0;
  const valid = observedSec >= 13;
  const full =
    data.completionReason === 'ended' &&
    progressRatio >= 0.9 &&
    observedSec >= Math.max(
      13,
      Math.floor(data.duration * 0.8)
    );

  const receipt = {
    version: LISTEN_RECEIPT_VERSION,
    receiptId,
    playerId: data.playerId,
    sessionId: data.sessionId,
    trackUid: data.trackUid,
    album: data.album,
    duration: data.duration,
    observedSec,
    finalPosition: data.lastPosition,
    progressRatio: Math.max(
      0,
      Math.min(1, progressRatio)
    ),
    valid,
    full,
    acceptedHeartbeats: data.acceptedHeartbeats,
    rejectedHeartbeats: data.rejectedHeartbeats,
    completionReason: data.completionReason,
    startedAt: data.startedAt,
    completedAt: data.completedAt,
    shadow: true,
    rewardGranted: false
  };

  const receiptPk = listenReceiptKey(
    data.playerId,
    receiptId
  );
  const oldReceiptRow = await kvGet(receiptPk);
  const oldReceipt = payload(oldReceiptRow);

  if (oldReceipt.progressApplied === true) {
    const progress = normalizeAchievementProgress(
      payload(await kvGet(
        achievementProgressKey(data.playerId)
      )),
      data.playerId
    );
    const rewards = await reconcileAchievementRewards(
      data.playerId,
      progress
    );

    return {
      receipt: oldReceipt,
      progress,
      rewards,
      duplicate: true
    };
  }

  if (!oldReceiptRow) {
    try {
      await kvInsert({
        pk: receiptPk,
        type: 'listenReceipt',
        owner: data.playerId,
        expiresAt: 0,
        data: {
          ...receipt,
          progressApplied: false
        }
      });
    } catch {}
  }

  const applied = await applyListenReceiptProgress(receipt);
  const rewards = await reconcileAchievementRewards(
    data.playerId,
    applied.progress
  );
  const completedReceipt = {
    ...receipt,
    progressApplied: true,
    rewardGranted: rewards.grants.length > 0,
    rewardAmount: rewards.grants.reduce(
      (sum, grant) => sum + grant.amount,
      0
    ),
    rewardIds: rewards.grants.map(
      grant => grant.achievementId
    )
  };

  await kvPut({
    pk: receiptPk,
    type: 'listenReceipt',
    owner: data.playerId,
    expiresAt: 0,
    data: completedReceipt
  });

  return {
    receipt: completedReceipt,
    progress: applied.progress,
    rewards,
    duplicate: applied.duplicate
  };
}

async function actionListenSessionStart(event, body) {
  const { playerId } = await requirePlayer(event, body);

  await enforceRateLimit({
    scope: 'listen_start',
    actor: playerId,
    limit: 40,
    windowMs: 60 * 1000
  });

  const track = listenTrackFromCatalog(body.trackUid);
  const deviceId =
    sanitizeId(body.deviceId, 120) ||
    'web';
  const key = listenActiveKey(
    playerId,
    deviceId
  );

  for (let attempt = 0; attempt < 10; attempt++) {
    let row = await kvGet(key);
    const current = normalizeListenSession(payload(row));

    if (
      row &&
      current.status === 'active' &&
      current.trackUid === track.uid &&
      current.deviceId === deviceId &&
      now() - current.lastHeartbeatAt <
        CFG.listenHeartbeatMaxGapMs
    ) {
      return {
        ok: true,
        duplicate: true,
        shadow: CFG.listeningReceiptsShadow,
        session: publicListenSession(current)
      };
    }

    const at = now();
    const session = normalizeListenSession({
      version: LISTEN_RECEIPT_VERSION,
      playerId,
      sessionId: rid('listen'),
      deviceId,
      trackUid: track.uid,
      album: track.album,
      duration: track.duration,
      variant: body.variant || 'audio',
      quality: body.quality || '',
      status: 'active',
      startedAt: at,
      lastHeartbeatAt: at,
      lastPosition: Math.max(
        0,
        Math.min(
          track.duration,
          num(body.position)
        )
      ),
      observedMs: 0,
      acceptedHeartbeats: 0,
      rejectedHeartbeats: 0,
      visibility: sanitizeId(
        body.visibility,
        20
      ),
      platform: sanitizeId(
        body.platform,
        30
      ),
      updatedAt: at
    });

    if (!row) {
      try {
        await kvInsert({
          pk: key,
          type: 'listenActive',
          owner: playerId,
          data: session
        });

        await persistListenSession(session);

        return {
          ok: true,
          duplicate: false,
          shadow: CFG.listeningReceiptsShadow,
          session: publicListenSession(session)
        };
      } catch {
        continue;
      }
    }

    if (current.status === 'active') {
      await persistListenSession({
        ...current,
        status: 'replaced',
        completedAt: at,
        completionReason: 'replaced',
        updatedAt: at
      }).catch(() => null);
    }

    if (!await kvCompareAndPut({
      row,
      type: 'listenActive',
      owner: playerId,
      data: session
    })) {
      continue;
    }

    await persistListenSession(session);

    return {
      ok: true,
      duplicate: false,
      shadow: CFG.listeningReceiptsShadow,
      session: publicListenSession(session)
    };
  }

  throw new Error('listen_session_start_conflict');
}

async function actionListenSessionHeartbeat(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const sessionId = sanitizeId(body.sessionId, 120);

  if (!sessionId) {
    throw new Error('listen_session_required');
  }

  for (let attempt = 0; attempt < 10; attempt++) {
    const resolved = await resolveListenSessionRow(
      playerId,
      sessionId
    );
    const { row, session } = resolved;

    if (
      !resolved.active ||
      !row ||
      session.sessionId !== sessionId ||
      session.status !== 'active'
    ) {
      throw new Error('listen_session_not_active');
    }

    if (
      now() - session.startedAt >
      CFG.listenSessionMaxMs
    ) {
      throw new Error('listen_session_expired');
    }

    const observation = applyListenObservation(
      session,
      body
    );

    if (observation.throttled) {
      return {
        ok: true,
        throttled: true,
        accepted: false,
        shadow: CFG.listeningReceiptsShadow,
        session: publicListenSession(session)
      };
    }

    if (!await kvCompareAndPut({
      row,
      type: 'listenActive',
      owner: playerId,
      data: observation.session
    })) {
      continue;
    }

    await persistListenSession(
      observation.session
    ).catch(() => null);

    return {
      ok: true,
      throttled: false,
      accepted: observation.accepted,
      creditedMs: observation.creditMs,
      shadow: CFG.listeningReceiptsShadow,
      session: publicListenSession(
        observation.session
      )
    };
  }

  throw new Error('listen_heartbeat_conflict');
}

async function actionListenSessionComplete(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const sessionId = sanitizeId(body.sessionId, 120);

  if (!sessionId) {
    throw new Error('listen_session_required');
  }

  for (let attempt = 0; attempt < 10; attempt++) {
    const resolved = await resolveListenSessionRow(
      playerId,
      sessionId
    );
    const row = resolved.row;
    const current = resolved.session;
    const useActive = resolved.active;

    if (
      !row ||
      current.playerId !== playerId ||
      current.sessionId !== sessionId
    ) {
      throw new Error('listen_session_not_found');
    }

    if (current.status === 'completed') {
      const finalized = await finalizeListenSession(current);

      return {
        ok: true,
        duplicate: true,
        shadow: CFG.listeningReceiptsShadow,
        rewardsEnabled: !CFG.listeningReceiptsShadow,
        receipt: finalized.receipt,
        rewards: finalized.rewards?.grants || [],
        wallet: finalized.rewards?.wallet
          ? publicShardWallet(finalized.rewards.wallet)
          : null,
        progress: publicAchievementProgress(
          finalized.progress
        )
      };
    }

    if (!['active', 'replaced'].includes(current.status)) {
      throw new Error('listen_session_not_completable');
    }

    const at = now();
    const observation = applyListenObservation(
      current,
      body,
      {
        completed: true,
        at
      }
    );

    const receiptId = `lr_${hash([
      playerId,
      sessionId,
      at
    ].join(':')).slice(0, 28)}`;

    const completed = normalizeListenSession({
      ...observation.session,
      status: 'completed',
      completedAt: at,
      completionReason: sanitizeId(
        body.reason || 'unknown',
        40
      ),
      receiptId,
      updatedAt: at
    });

    const changed = await kvCompareAndPut({
      row,
      type: useActive
        ? 'listenActive'
        : 'listenSession',
      owner: playerId,
      expiresAt: useActive
        ? 0
        : num(row.expires_at) ||
          at + LISTEN_SESSION_RETENTION_MS,
      data: completed
    });

    if (!changed) continue;

    if (useActive) {
      await persistListenSession(completed);
    }

    const finalized = await finalizeListenSession(completed);

    return {
      ok: true,
      duplicate: false,
      acceptedFinalObservation:
        observation.accepted === true,
      shadow: CFG.listeningReceiptsShadow,
      rewardsEnabled: !CFG.listeningReceiptsShadow,
      receipt: finalized.receipt,
      rewards: finalized.rewards?.grants || [],
      wallet: finalized.rewards?.wallet
        ? publicShardWallet(finalized.rewards.wallet)
        : null,
      progress: publicAchievementProgress(
        finalized.progress
      )
    };
  }

  throw new Error('listen_session_complete_conflict');
}

async function actionBackupAchievementReceipt(event, body) {
  const secret = headerValue(
    event,
    'x-vi3-backup-secret'
  );

  if (
    !CFG.backupReceiptSecret ||
    !timingSafeEqualText(
      secret,
      CFG.backupReceiptSecret
    )
  ) {
    throw new Error('bad_backup_receipt_secret');
  }

  const ownerYandexId = safe(body.ownerYandexId);
  const payloadHash = safe(body.payloadHash).toLowerCase();

  if (
    !ownerYandexId ||
    !/^[a-f0-9]{64}$/.test(payloadHash)
  ) {
    throw new Error('bad_backup_receipt');
  }

  const playerId = makeFriendId(ownerYandexId);
  const receiptId = `backup_${hash(
    `${ownerYandexId}:${payloadHash}`
  ).slice(0, 40)}`;
  const key = achievementProgressKey(playerId);

  for (let attempt = 0; attempt < 10; attempt++) {
    let row = await kvGet(key);

    if (!row) {
      try {
        await kvInsert({
          pk: key,
          type: 'achievementProgress',
          owner: playerId,
          data: normalizeAchievementProgress(
            {},
            playerId
          )
        });
      } catch {}

      row = await kvGet(key);
      if (!row) continue;
    }

    const progress = normalizeAchievementProgress(
      payload(row),
      playerId
    );

    if (progress.backupReceiptIds.includes(receiptId)) {
      const rewards = await reconcileAchievementRewards(
        playerId,
        progress
      );

      return {
        ok: true,
        duplicate: true,
        receiptId,
        shadow: CFG.backupRewardsShadow,
        rewardsEnabled: !CFG.backupRewardsShadow,
        rewards: rewards.grants,
        wallet: publicShardWallet(rewards.wallet),
        progress: publicAchievementProgress(progress)
      };
    }

    const next = normalizeAchievementProgress({
      ...progress,
      backupSaves: progress.backupSaves + 1,
      backupReceiptIds: [
        ...progress.backupReceiptIds,
        receiptId
      ],
      updatedAt: now()
    }, playerId);

    if (!await kvCompareAndPut({
      row,
      type: 'achievementProgress',
      owner: playerId,
      data: next
    })) {
      continue;
    }

    const rewards = await reconcileAchievementRewards(
      playerId,
      next
    );

    return {
      ok: true,
      duplicate: false,
      receiptId,
      shadow: CFG.backupRewardsShadow,
      rewardsEnabled: !CFG.backupRewardsShadow,
      rewards: rewards.grants,
      wallet: publicShardWallet(rewards.wallet),
      progress: publicAchievementProgress(next)
    };
  }

  throw new Error('backup_receipt_conflict');
}

async function actionAchievementRewardStatus(event, body) {
  const { playerId } = await requirePlayer(event, body);

  const [legacyActiveRow, deviceActiveRows] =
    await Promise.all([
      kvGet(listenActiveKey(playerId)),
      kvPrefix(
        `${listenActiveKey(playerId)}:`,
        30
      )
    ]);

  const activeSessions = [
    legacyActiveRow,
    ...deviceActiveRows
  ]
    .filter(Boolean)
    .map(payload)
    .map(normalizeListenSession)
    .filter(session =>
      session.playerId === playerId &&
      session.status === 'active'
    )
    .filter((session, index, rows) =>
      rows.findIndex(item =>
        item.sessionId === session.sessionId
      ) === index
    )
    .sort((left, right) =>
      num(right.updatedAt) - num(left.updatedAt)
    );

  const active = activeSessions[0] ||
    normalizeListenSession();

  const progress = normalizeAchievementProgress(
    payload(await kvGet(
      achievementProgressKey(playerId)
    )),
    playerId
  );
  const favoriteState = normalizeFavoriteState(
    payload(await kvGet(
      favoriteStateKey(playerId)
    )),
    playerId
  );

  const rewards = await reconcileAchievementRewards(
    playerId,
    progress
  );

  return {
    ok: true,
    shadow: CFG.listeningReceiptsShadow,
    rewardsEnabled: !CFG.listeningReceiptsShadow,
    currency: {
      code: 'shards',
      symbol: '♦',
      rewardPolicy: 'server_catalog',
      legacyNominalMigrated: true
    },
    catalog: {
      configured: LISTEN_TRACK_CATALOG.size > 0,
      tracks: LISTEN_TRACK_CATALOG.size,
      rewards: ACHIEVEMENT_REWARD_CATALOG.length,
      rewardItems: publicAchievementRewardItems({
        playerId,
        progress,
        favoriteState,
        wallet: rewards.wallet
      })
    },
    activeSession:
      active.playerId === playerId &&
      active.status === 'active'
        ? publicListenSession(active)
        : null,
    activeSessions:
      activeSessions.map(publicListenSession),
    grants: rewards.grants,
    wallet: publicShardWallet(rewards.wallet),
    favorites: {
      shadow: CFG.favoriteRewardsShadow,
      rewardsEnabled:
        !CFG.favoriteRewardsShadow,
      state: publicFavoriteState(favoriteState)
    },
    progress: publicAchievementProgress(progress)
  };
}

const SHARD_WALLET_VERSION = 1;
const REGISTRATION_SHARD_REWARD = 100;
const WALLET_GRANT_HISTORY = 300;

const SHARD_AVATAR_CATALOG = Object.freeze([
  Object.freeze({
    id: 'avatar_dragon',
    avatar: '🐉',
    title: 'Дракон Витрины',
    price: 100
  }),
  Object.freeze({
    id: 'avatar_planet',
    avatar: '🪐',
    title: 'Осколок Вселенной',
    price: 500
  }),
  Object.freeze({
    id: 'avatar_crown',
    avatar: '👑',
    title: 'Корона Башни',
    price: 1000
  })
]);

function walletKey(playerId) {
  return `wallet:${sanitizeId(playerId, 96)}`;
}

function normalizeShardWallet(raw, playerId) {
  const wallet = raw && typeof raw === 'object'
    ? raw
    : {};

  const locks = Object.fromEntries(
    Object.entries(
      wallet.locks && typeof wallet.locks === 'object'
        ? wallet.locks
        : {}
    )
      .map(([matchId, amount]) => [
        sanitizeId(matchId, 120),
        Math.max(0, Math.floor(num(amount)))
      ])
      .filter(([matchId, amount]) => matchId && amount > 0)
      .slice(-100)
  );

  const operations = Object.fromEntries(
    Object.entries(
      wallet.operations && typeof wallet.operations === 'object'
        ? wallet.operations
        : {}
    )
      .map(([operationId, operation]) => [
        sanitizeId(operationId, 180),
        {
          kind: sanitizeId(operation?.kind, 30),
          matchId: sanitizeId(operation?.matchId, 120),
          amount: Math.max(0, Math.floor(num(operation?.amount))),
          at: num(operation?.at)
        }
      ])
      .filter(([operationId]) => operationId)
      .sort((a, b) => num(a[1]?.at) - num(b[1]?.at))
      .slice(-300)
  );

  const grantIds = [...new Set([
    ...(
      Array.isArray(wallet.grantIds)
        ? wallet.grantIds
        : []
    ),
    ...Object.entries(operations)
      .filter(([, operation]) =>
        operation?.kind === 'grant' ||
        operation?.kind === 'achievement_grant'
      )
      .map(([operationId]) => operationId)
  ]
    .map(operationId => sanitizeId(operationId, 180))
    .filter(Boolean)
  )];

  const lockedByRecords = Object.values(locks)
    .reduce((sum, amount) => sum + amount, 0);

  return {
    version: SHARD_WALLET_VERSION,
    playerId: sanitizeId(playerId, 96),
    balance: Math.max(0, Math.floor(num(wallet.balance))),
    locked: Math.max(
      lockedByRecords,
      Math.max(0, Math.floor(num(wallet.locked)))
    ),
    locks,
    operations,
    grantIds,
    earned: Math.max(0, Math.floor(num(wallet.earned))),
    spent: Math.max(0, Math.floor(num(wallet.spent))),
    purchasedAvatarIds: [...new Set(
      (Array.isArray(wallet.purchasedAvatarIds)
        ? wallet.purchasedAvatarIds
        : [])
        .map(value => sanitizeId(value, 80))
        .filter(Boolean)
    )].slice(0, 100),
    purchaseIds: [...new Set(
      (Array.isArray(wallet.purchaseIds)
        ? wallet.purchaseIds
        : [])
        .map(value => sanitizeId(value, 120))
        .filter(Boolean)
    )].slice(-100),
    createdAt: num(wallet.createdAt) || now(),
    updatedAt: num(wallet.updatedAt) || now()
  };
}

function publicShardWallet(wallet) {
  const normalized = normalizeShardWallet(
    wallet,
    wallet?.playerId
  );

  return {
    available: true,
    version: normalized.version,
    shards: normalized.balance,
    locked: normalized.locked,
    spendable: Math.max(
      0,
      normalized.balance - normalized.locked
    ),
    earned: normalized.earned,
    spent: normalized.spent,
    purchasedAvatarIds: normalized.purchasedAvatarIds,
    purchasedAvatars: SHARD_AVATAR_CATALOG
      .filter(item =>
        normalized.purchasedAvatarIds.includes(item.id)
      )
      .map(item => ({
        id: item.id,
        avatar: item.avatar,
        title: item.title
      })),
    updatedAt: normalized.updatedAt
  };
}

async function getOrCreateShardWallet(playerId) {
  const key = walletKey(playerId);
  let row = await kvGet(key);

  if (row) {
    return {
      row,
      wallet: normalizeShardWallet(
        payload(row),
        playerId
      )
    };
  }

  const wallet = normalizeShardWallet({}, playerId);

  try {
    await kvInsert({
      pk: key,
      type: 'wallet',
      owner: playerId,
      data: wallet
    });
  } catch {
    // Параллельный запрос мог создать wallet первым.
  }

  row = await kvGet(key);
  if (!row) throw new Error('wallet_create_failed');

  return {
    row,
    wallet: normalizeShardWallet(
      payload(row),
      playerId
    )
  };
}
async function ensureRegistrationShardGrant(playerId) {
  const operationId = [
    'grant',
    'registration',
    sanitizeId(playerId, 96)
  ].join(':');

  for (let attempt = 0; attempt < 10; attempt++) {
    const { row, wallet } =
      await getOrCreateShardWallet(playerId);

    if (
      wallet.grantIds?.includes(operationId) ||
      wallet.operations?.[operationId]
    ) {
      return {
        ok: true,
        duplicate: true,
        operationId,
        amount: REGISTRATION_SHARD_REWARD,
        wallet
      };
    }

    const at = now();
    const next = {
      ...wallet,
      balance:
        wallet.balance +
        REGISTRATION_SHARD_REWARD,
      earned:
        wallet.earned +
        REGISTRATION_SHARD_REWARD,
      grantIds: [...new Set([
        ...(wallet.grantIds || []),
        operationId
      ])],
      operations: trimWalletOperations({
        ...(wallet.operations || {}),
        [operationId]: {
          kind: 'grant',
          matchId: 'registration',
          amount: REGISTRATION_SHARD_REWARD,
          at
        }
      }),
      updatedAt: at
    };

    const changed = await kvCompareAndPut({
      row,
      type: 'wallet',
      owner: playerId,
      data: next
    });

    if (!changed) {
      const current = normalizeShardWallet(
        payload(await kvGet(walletKey(playerId))),
        playerId
      );

      if (current.grantIds.includes(operationId)) {
        return {
          ok: true,
          duplicate: true,
          operationId,
          amount: REGISTRATION_SHARD_REWARD,
          wallet: current
        };
      }

      continue;
    }

    return {
      ok: true,
      duplicate: false,
      operationId,
      amount: REGISTRATION_SHARD_REWARD,
      wallet: next
    };
  }

  throw new Error('wallet_registration_grant_conflict');
}
function achievementRewardOperationId(
  playerId,
  achievementId
) {
  return [
    'grant',
    'achievement',
    sanitizeId(achievementId, 120),
    sanitizeId(playerId, 96)
  ].join(':');
}

async function applyAchievementShardGrant({
  playerId,
  achievementId,
  amount,
  validatorVersion = 1
}) {
  const cleanId = sanitizeId(achievementId, 120);
  const reward = Math.max(0, Math.floor(num(amount)));
  const operationId = achievementRewardOperationId(
    playerId,
    cleanId
  );

  if (!cleanId || !reward) {
    throw new Error('achievement_reward_invalid');
  }

  for (let attempt = 0; attempt < 10; attempt++) {
    const { row, wallet } =
      await getOrCreateShardWallet(playerId);

    if (wallet.grantIds?.includes(operationId)) {
      return {
        ok: true,
        duplicate: true,
        operationId,
        achievementId: cleanId,
        amount: reward,
        wallet
      };
    }

    const at = now();
    const next = {
      ...wallet,
      balance: wallet.balance + reward,
      earned: wallet.earned + reward,
      grantIds: [...new Set([
        ...(wallet.grantIds || []),
        operationId
      ])],
      operations: trimWalletOperations({
        ...(wallet.operations || {}),
        [operationId]: {
          kind: 'achievement_grant',
          matchId: cleanId,
          amount: reward,
          validatorVersion,
          at
        }
      }),
      updatedAt: at
    };

    if (!await kvCompareAndPut({
      row,
      type: 'wallet',
      owner: playerId,
      data: next
    })) {
      continue;
    }

    return {
      ok: true,
      duplicate: false,
      operationId,
      achievementId: cleanId,
      amount: reward,
      wallet: next
    };
  }

  throw new Error('achievement_reward_grant_conflict');
}

function achievementMetricValue(
  progress,
  reward,
  context = {}
) {
  if (reward.metric === 'validPlays') {
    return progress.validPlays;
  }

  if (reward.metric === 'fullPlays') {
    return progress.fullPlays;
  }

  if (reward.metric === 'totalSec') {
    return progress.totalSec;
  }

  if (reward.metric === 'uniqueTracks') {
    return Object.keys(progress.uniqueTracks || {}).length;
  }

  if (reward.metric === 'maxOneTrackFull') {
    return Math.max(
      0,
      ...Object.values(progress.perTrackFull || {})
    );
  }

  if (reward.metric === 'streak') {
    return calculateServerStreak(progress.activeDays);
  }
  if (reward.metric === 'favCount') {
    return favoriteRewardCount(
      context.favoriteState || {}
    );
  }

  if (reward.metric === 'backupSaves') {
    return Math.max(
      0,
      Math.floor(num(progress.backupSaves))
    );
  }

  if (reward.metric === 'albumComplete') {
    const tracks = LISTEN_ALBUM_TRACKS.get(
      reward.album
    ) || [];

    return tracks.length > 0 &&
      tracks.every(uid =>
        num(progress.perTrackFull?.[uid]) > 0
      )
      ? 1
      : 0;
  }

  return 0;
}

function achievementRewardEnabled(reward) {
  if (reward.channel === 'favorite') {
    return !CFG.favoriteRewardsShadow;
  }

  if (reward.channel === 'backup') {
    return !CFG.backupRewardsShadow;
  }

  return !CFG.listeningReceiptsShadow;
}

function publicAchievementRewardItems({
  playerId,
  progress,
  favoriteState,
  wallet
}) {
  const grantIds = new Set(
    Array.isArray(wallet?.grantIds)
      ? wallet.grantIds
      : []
  );

  return ACHIEVEMENT_REWARD_CATALOG.map(reward => {
    const current = achievementMetricValue(
      progress,
      reward,
      { favoriteState }
    );
    const operationId = achievementRewardOperationId(
      playerId,
      reward.id
    );

    return {
      id: reward.id,
      metric: reward.metric,
      channel: reward.channel || 'listening',
      target: reward.target,
      current,
      amount: reward.amount,
      album: reward.album || '',
      validatorVersion: reward.validatorVersion,
      eligible: current >= reward.target,
      awarded: grantIds.has(operationId),
      rewardsEnabled: achievementRewardEnabled(reward)
    };
  });
}

async function reconcileAchievementRewards(
  playerId,
  progressRaw
) {
  const progress = normalizeAchievementProgress(
    progressRaw,
    playerId
  );
  const grants = [];
  let latestWallet = null;

  const favoriteState = normalizeFavoriteState(
    payload(await kvGet(
      favoriteStateKey(playerId)
    )),
    playerId
  );

  for (const reward of ACHIEVEMENT_REWARD_CATALOG) {
    if (!achievementRewardEnabled(reward)) {
      continue;
    }

    if (
      achievementMetricValue(
        progress,
        reward,
        { favoriteState }
      ) < reward.target
    ) {
      continue;
    }

    const grant = await applyAchievementShardGrant({
      playerId,
      achievementId: reward.id,
      amount: reward.amount,
      validatorVersion: reward.validatorVersion
    });

    latestWallet = grant.wallet;

    if (!grant.duplicate) {
      grants.push({
        achievementId: reward.id,
        amount: reward.amount,
        operationId: grant.operationId,
        validatorVersion: reward.validatorVersion
      });
    }
  }

  if (!latestWallet) {
    const registration =
      await ensureRegistrationShardGrant(playerId);
    latestWallet = registration.wallet;
  }

  return {
    enabled:
      !CFG.listeningReceiptsShadow ||
      !CFG.favoriteRewardsShadow ||
      !CFG.backupRewardsShadow,
    grants,
    wallet: latestWallet
  };
}

async function actionWalletGet(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const grant = await ensureRegistrationShardGrant(
    playerId
  );

  return {
    ok: true,
    registrationGrant: {
      amount: grant.amount,
      duplicate: grant.duplicate,
      operationId: grant.operationId
    },
    wallet: publicShardWallet(grant.wallet),
    catalog: SHARD_AVATAR_CATALOG
  };
}
async function actionWalletRegistrationBackfill(
  event,
  body
) {
  const admin =
    headerValue(event, 'x-vi3-admin') ||
    safe(body.adminSecret);

  if (
    !CFG.adminSecret ||
    !timingSafeEqualText(admin, CFG.adminSecret)
  ) {
    throw new Error('bad_admin_secret');
  }

  const limit = Math.max(
    1,
    Math.min(1000, Math.floor(num(body.limit, 1000)))
  );
  const rows = await kvPrefix('player:', limit);
  const results = [];

  for (const row of rows) {
    const playerId = sanitizeId(
      payload(row)?.playerId ||
      row.owner,
      96
    );

    if (!playerId) continue;

    try {
      const grant =
        await ensureRegistrationShardGrant(playerId);

      results.push({
        playerId,
        ok: true,
        duplicate: grant.duplicate,
        amount: grant.amount
      });
    } catch (error) {
      results.push({
        playerId,
        ok: false,
        error: safe(error?.message)
      });
    }
  }

  return {
    ok: true,
    scanned: rows.length,
    granted: results.filter(
      item => item.ok && !item.duplicate
    ).length,
    duplicates: results.filter(
      item => item.ok && item.duplicate
    ).length,
    failed: results.filter(
      item => !item.ok
    ).length,
    results
  };
}

async function actionWalletPurchaseAvatar(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const itemId = sanitizeId(body.itemId, 80);
  const purchaseId = sanitizeId(body.purchaseId, 120);

  if (!purchaseId) {
    throw new Error('wallet_purchase_id_required');
  }

  const item = SHARD_AVATAR_CATALOG.find(
    candidate => candidate.id === itemId
  );

  if (!item) {
    throw new Error('wallet_item_not_found');
  }

  for (let attempt = 0; attempt < 8; attempt++) {
    const { row, wallet } =
      await getOrCreateShardWallet(playerId);

    if (wallet.purchaseIds.includes(purchaseId)) {
      return {
        ok: true,
        duplicate: true,
        item,
        wallet: publicShardWallet(wallet)
      };
    }

    if (wallet.purchasedAvatarIds.includes(item.id)) {
      return {
        ok: true,
        duplicate: true,
        owned: true,
        item,
        wallet: publicShardWallet(wallet)
      };
    }

    const spendable = Math.max(
      0,
      wallet.balance - wallet.locked
    );

    if (spendable < item.price) {
      return {
        ok: false,
        reason: 'wallet_insufficient_shards',
        required: item.price,
        available: spendable,
        wallet: publicShardWallet(wallet)
      };
    }

    const next = {
      ...wallet,
      balance: wallet.balance - item.price,
      spent: wallet.spent + item.price,
      purchasedAvatarIds: [
        ...wallet.purchasedAvatarIds,
        item.id
      ],
      purchaseIds: [
        ...wallet.purchaseIds,
        purchaseId
      ].slice(-100),
      updatedAt: now()
    };

    const changed = await kvCompareAndPut({
      row,
      type: 'wallet',
      owner: playerId,
      data: next
    });

    if (!changed) continue;

    return {
      ok: true,
      duplicate: false,
      item,
      wallet: publicShardWallet(next)
    };
  }

  throw new Error('wallet_purchase_conflict');
}

const RANKED_STAKE_AMOUNT = 100;
const ESCROW_VERSION = 1;
const ESCROW_OPERATION_HISTORY = 300;

function rankedEscrowKey(matchId) {
  return `escrow:${sanitizeId(matchId, 120)}`;
}

function walletOperationId(kind, matchId, playerId) {
  return [
    sanitizeId(kind, 30),
    sanitizeId(matchId, 120),
    sanitizeId(playerId, 96)
  ].join(':');
}

function normalizeRankedEscrow(raw = {}) {
  const participants = [...new Set(
    (Array.isArray(raw.participants)
      ? raw.participants
      : [])
      .map(playerId => sanitizeId(playerId, 96))
      .filter(Boolean)
  )].slice(0, 2);

  return {
    version: ESCROW_VERSION,
    matchId: sanitizeId(raw.matchId, 120),
    roomId: sanitizeId(raw.roomId, 120),
    participants,
    amountEach: Math.max(
      0,
      Math.floor(num(raw.amountEach, RANKED_STAKE_AMOUNT))
    ),
    total: Math.max(
      0,
      Math.floor(num(
        raw.total,
        participants.length * RANKED_STAKE_AMOUNT
      ))
    ),
    status: sanitizeId(raw.status || 'locking', 30),
    locks:
      raw.locks && typeof raw.locks === 'object'
        ? raw.locks
        : {},
    operations:
      raw.operations && typeof raw.operations === 'object'
        ? raw.operations
        : {},
    winnerId: sanitizeId(raw.winnerId, 96),
    loserId: sanitizeId(raw.loserId, 96),
    createdAt: num(raw.createdAt) || now(),
    fundedAt: num(raw.fundedAt),
    paidAt: num(raw.paidAt),
    refundedAt: num(raw.refundedAt),
    updatedAt: num(raw.updatedAt) || now()
  };
}

function publicRankedEscrow(escrow) {
  const data = normalizeRankedEscrow(escrow);

  return {
    required: true,
    version: data.version,
    status: data.status,
    stakeEach: data.amountEach,
    escrow: data.total,
    lockedPlayers: data.participants.filter(
      playerId => data.locks?.[playerId]?.status === 'locked'
    ).length,
    participants: data.participants.length,
    fundedAt: data.fundedAt,
    paidAt: data.paidAt,
    refundedAt: data.refundedAt,
    updatedAt: data.updatedAt
  };
}

async function getOrCreateRankedEscrow(match) {
  const key = rankedEscrowKey(match.matchId);
  let row = await kvGet(key);

  if (row) {
    return {
      row,
      escrow: normalizeRankedEscrow(payload(row))
    };
  }

  const createdAt = now();
  const escrow = normalizeRankedEscrow({
    matchId: match.matchId,
    roomId: match.roomId,
    participants: match.participants,
    amountEach: RANKED_STAKE_AMOUNT,
    total: RANKED_STAKE_AMOUNT * 2,
    status: 'locking',
    locks: {},
    operations: {},
    createdAt,
    updatedAt: createdAt
  });

  try {
    await kvInsert({
      pk: key,
      type: 'escrow',
      owner: match.roomId,
      expiresAt:
        num(match.expiresAt) ||
        createdAt + CFG.roomTtlMs,
      data: escrow
    });
  } catch {
    // Параллельный участник мог создать escrow первым.
  }

  row = await kvGet(key);
  if (!row) throw new Error('ranked_escrow_create_failed');

  return {
    row,
    escrow: normalizeRankedEscrow(payload(row))
  };
}

function trimWalletOperations(operations = {}) {
  return Object.fromEntries(
    Object.entries(operations)
      .sort((a, b) => num(a[1]?.at) - num(b[1]?.at))
      .slice(-ESCROW_OPERATION_HISTORY)
  );
}

async function applyWalletEscrowOperation({
  playerId,
  matchId,
  kind,
  amount,
  won = false
}) {
  const operationKind = kind === 'payout'
    ? 'payout'
    : kind;
  const operationId = walletOperationId(
    operationKind,
    matchId,
    playerId
  );
  const stake = Math.max(0, Math.floor(num(amount)));

  if (!stake) throw new Error('wallet_operation_amount_invalid');

  for (let attempt = 0; attempt < 10; attempt++) {
    const { row, wallet } =
      await getOrCreateShardWallet(playerId);

    if (wallet.operations?.[operationId]) {
      return {
        ok: true,
        duplicate: true,
        operationId,
        wallet
      };
    }

    const locks = { ...(wallet.locks || {}) };
    const currentLock = Math.max(
      0,
      Math.floor(num(locks[matchId]))
    );

    let nextBalance = wallet.balance;
    let nextLocked = wallet.locked;
    let nextEarned = wallet.earned;
    let nextSpent = wallet.spent;

    if (kind === 'stake') {
      if (currentLock > 0 && currentLock !== stake) {
        throw new Error('wallet_stake_lock_conflict');
      }

      if (!currentLock) {
        const spendable = Math.max(
          0,
          wallet.balance - wallet.locked
        );

        if (spendable < stake) {
          const error = new Error('wallet_insufficient_shards');
          error.httpStatus = 409;
          throw error;
        }

        locks[matchId] = stake;
        nextLocked += stake;
      }
    } else if (kind === 'payout') {
      if (currentLock < stake) {
        throw new Error('wallet_payout_lock_missing');
      }

      delete locks[matchId];
      nextLocked = Math.max(0, nextLocked - stake);

      if (won) {
        nextBalance += stake;
        nextEarned += stake;
      } else {
        if (nextBalance < stake) {
          throw new Error('wallet_payout_balance_invalid');
        }

        nextBalance -= stake;
        nextSpent += stake;
      }
    } else if (kind === 'refund') {
      if (currentLock > 0) {
        delete locks[matchId];
        nextLocked = Math.max(0, nextLocked - currentLock);
      }
    } else {
      throw new Error('wallet_operation_kind_invalid');
    }

    const at = now();
    const next = {
      ...wallet,
      balance: nextBalance,
      locked: nextLocked,
      locks,
      operations: trimWalletOperations({
        ...(wallet.operations || {}),
        [operationId]: {
          kind,
          matchId,
          amount: stake,
          at
        }
      }),
      earned: nextEarned,
      spent: nextSpent,
      updatedAt: at
    };

    const changed = await kvCompareAndPut({
      row,
      type: 'wallet',
      owner: playerId,
      data: next
    });

    if (!changed) continue;

    return {
      ok: true,
      duplicate: false,
      operationId,
      wallet: next
    };
  }

  throw new Error('wallet_operation_conflict');
}

async function updateRankedEscrow(matchId, updater) {
  const key = rankedEscrowKey(matchId);

  for (let attempt = 0; attempt < 10; attempt++) {
    const row = await kvGet(key);
    if (!row) throw new Error('ranked_escrow_not_found');

    const escrow = normalizeRankedEscrow(payload(row));
    const next = normalizeRankedEscrow(
      updater(escrow) || escrow
    );

    if (
      stableStringify(next) === stableStringify(escrow)
    ) {
      return escrow;
    }

    if (await kvCompareAndPut({
      row,
      type: 'escrow',
      owner: escrow.roomId,
      expiresAt: num(row.expires_at),
      data: next
    })) {
      return next;
    }
  }

  throw new Error('ranked_escrow_conflict');
}

async function reconcileEscrowFunding(match) {
  await getOrCreateRankedEscrow(match);

  const walletLocks = {};

  for (const playerId of match.participants || []) {
    const { wallet } = await getOrCreateShardWallet(playerId);
    walletLocks[playerId] = Math.max(
      0,
      Math.floor(num(wallet.locks?.[match.matchId]))
    );
  }

  return updateRankedEscrow(match.matchId, escrow => {
    if (
      ['paying', 'paid', 'refunding', 'refunded']
        .includes(escrow.status)
    ) {
      return escrow;
    }

    const locks = { ...(escrow.locks || {}) };

    escrow.participants.forEach(playerId => {
      if (walletLocks[playerId] >= escrow.amountEach) {
        locks[playerId] = {
          status: 'locked',
          amount: escrow.amountEach,
          operationId: walletOperationId(
            'stake',
            escrow.matchId,
            playerId
          ),
          lockedAt:
            num(locks[playerId]?.lockedAt) ||
            now()
        };
      }
    });

    const funded = escrow.participants.length === 2 &&
      escrow.participants.every(
        playerId => locks[playerId]?.status === 'locked'
      );

    return {
      ...escrow,
      locks,
      status: funded ? 'funded' : 'locking',
      fundedAt:
        funded
          ? escrow.fundedAt || now()
          : 0,
      updatedAt: now()
    };
  });
}

async function updateRankedMatchEconomy(matchId, economy) {
  const key = rankedMatchKey(matchId);

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await kvGet(key);
    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);
    const next = {
      ...match,
      economy,
      updatedAt: now()
    };

    if (await kvCompareAndPut({
      row,
      type: 'rankedMatch',
      owner: match.roomId,
      expiresAt: num(row.expires_at),
      data: next
    })) {
      return next;
    }
  }

  throw new Error('ranked_match_economy_conflict');
}

async function markEscrowOperation({
  matchId,
  playerId,
  operationId,
  status
}) {
  return updateRankedEscrow(matchId, escrow => ({
    ...escrow,
    operations: {
      ...(escrow.operations || {}),
      [playerId]: {
        operationId,
        status,
        at: now()
      }
    },
    updatedAt: now()
  }));
}

async function reconcileRankedEconomy(match) {
  if (match.economy?.required !== true) return match;

  let escrow = await reconcileEscrowFunding(match);

  if (!isRankedTerminal(match.status)) {
    return updateRankedMatchEconomy(
      match.matchId,
      publicRankedEscrow(escrow)
    );
  }

  const payoutTerminal = [
    'settled',
    'forfeited'
  ].includes(match.status);

  const refundTerminal = [
    'aborted',
    'disputed',
    'refunded'
  ].includes(match.status);

  if (!payoutTerminal && !refundTerminal) return match;

  if (payoutTerminal) {
    const winnerId = sanitizeId(
      match.settlement?.winnerId,
      96
    );
    const loserId = sanitizeId(
      match.settlement?.loserId,
      96
    );

    if (!winnerId || !loserId) {
      throw new Error('ranked_escrow_settlement_missing');
    }

    escrow = await updateRankedEscrow(
      match.matchId,
      current => ({
        ...current,
        status: current.status === 'paid'
          ? 'paid'
          : 'paying',
        winnerId,
        loserId,
        updatedAt: now()
      })
    );

    if (escrow.status !== 'paid') {
      for (const playerId of [winnerId, loserId]) {
        const result = await applyWalletEscrowOperation({
          playerId,
          matchId: match.matchId,
          kind: 'payout',
          amount: escrow.amountEach,
          won: playerId === winnerId
        });

        escrow = await markEscrowOperation({
          matchId: match.matchId,
          playerId,
          operationId: result.operationId,
          status: 'paid'
        });
      }

      escrow = await updateRankedEscrow(
        match.matchId,
        current => ({
          ...current,
          status: 'paid',
          paidAt: current.paidAt || now(),
          updatedAt: now()
        })
      );
    }
  }

  if (refundTerminal) {
    escrow = await updateRankedEscrow(
      match.matchId,
      current => ({
        ...current,
        status: current.status === 'refunded'
          ? 'refunded'
          : 'refunding',
        updatedAt: now()
      })
    );

    if (escrow.status !== 'refunded') {
      for (const playerId of escrow.participants) {
        const result = await applyWalletEscrowOperation({
          playerId,
          matchId: match.matchId,
          kind: 'refund',
          amount: escrow.amountEach
        });

        escrow = await markEscrowOperation({
          matchId: match.matchId,
          playerId,
          operationId: result.operationId,
          status: 'refunded'
        });
      }

      escrow = await updateRankedEscrow(
        match.matchId,
        current => ({
          ...current,
          status: 'refunded',
          refundedAt: current.refundedAt || now(),
          updatedAt: now()
        })
      );
    }
  }

  return updateRankedMatchEconomy(
    match.matchId,
    publicRankedEscrow(escrow)
  );
}

async function actionRankedStakePrepare(event, body) {
  const {
    playerId,
    matchId,
    match
  } = await requireRankedMatchPlayer(event, body);

  if (isRankedTerminal(match.status)) {
    const current = await reconcileRankedEconomy(match);

    return {
      ok: true,
      duplicate: true,
      match: publicRankedMatch(current, playerId)
    };
  }

  if (match.status !== 'pending') {
    throw rankedRpsError('ranked_stake_match_not_pending');
  }

  if (sanitizeId(match.rps?.firstPlayerId, 96)) {
    throw rankedRpsError('ranked_stake_after_rps_forbidden');
  }

  const escrow = await getOrCreateRankedEscrow(match);

  const operation = await applyWalletEscrowOperation({
    playerId,
    matchId,
    kind: 'stake',
    amount: escrow.escrow.amountEach
  });

  await markEscrowOperation({
    matchId,
    playerId,
    operationId: operation.operationId,
    status: 'locked'
  });

  const funded = await reconcileEscrowFunding(match);
  const current = await updateRankedMatchEconomy(
    matchId,
    publicRankedEscrow(funded)
  );

  return {
    ok: true,
    duplicate: operation.duplicate,
    playerId,
    operationId: operation.operationId,
    wallet: publicShardWallet(operation.wallet),
    escrow: publicRankedEscrow(funded),
    match: publicRankedMatch(current, playerId)
  };
}

const RANKED_GAME_ID = 'war_hearts';
const RANKED_BOARD_SIZE = 10;
const RANKED_FLEET = [4, 3, 3, 2, 2, 2, 1, 1, 1, 1];
const RANKED_MAX_TRANSCRIPT = 200;
const RANKED_SETTLEMENT_HISTORY = 100;
const RANKED_FORFEIT_GRACE_MS = 2 * 60 * 1000;
const RANKED_SUBMISSION_TIMEOUT_MS = 5 * 60 * 1000;
const RANKED_ABANDONED_TIMEOUT_MS = 6 * 60 * 60 * 1000;
const RANKED_RPS_MAX_ROUNDS = 20;
const RANKED_RPS_CHOICES = new Set([
  'rock',
  'scissors',
  'paper'
]);

const RANKED_TERMINAL_STATUSES = new Set([
  'settled',
  'forfeited',
  'disputed',
  'aborted',
  'refunded'
]);

const RANKED_TRANSITIONS = Object.freeze({
  pending: new Set([
    'forfeit_pending',
    'settling',
    'disputed',
    'aborted'
  ]),
  forfeit_pending: new Set([
    'settling',
    'disputed',
    'aborted'
  ]),
  settling: new Set([
    'settled',
    'forfeited',
    'disputed',
    'refunded'
  ]),
  disputed: new Set([
    'refunded'
  ])
});

function isRankedTerminal(status) {
  return RANKED_TERMINAL_STATUSES.has(safe(status));
}

function transitionRankedMatch(match, nextStatus, {
  reason = '',
  actorId = '',
  extra = {}
} = {}) {
  const current = safe(match?.status || 'pending');
  const next = safe(nextStatus);

  if (current === next) return match;

  if (!RANKED_TRANSITIONS[current]?.has(next)) {
    throw new Error(
      `ranked_transition_forbidden:${current}:${next}`
    );
  }

  const at = now();

  return {
    ...match,
    ...extra,
    status: next,
    terminalReason: safe(reason).slice(0, 120),
    terminalActorId: sanitizeId(actorId, 96),
    updatedAt: at,
    ...(isRankedTerminal(next)
      ? { terminalAt: at }
      : {})
  };
}

function rankedRpsCommitHash({
  matchId,
  round,
  playerId,
  choice,
  salt
}) {
  return hash([
    sanitizeId(matchId, 120),
    Math.max(1, Math.floor(num(round, 1))),
    sanitizeId(playerId, 96),
    sanitizeId(choice, 20),
    safe(salt).slice(0, 160)
  ].join(':'));
}

function compareRankedRps(left, right) {
  if (left === right) return 'draw';

  if (
    (left === 'rock' && right === 'scissors') ||
    (left === 'scissors' && right === 'paper') ||
    (left === 'paper' && right === 'rock')
  ) {
    return 'left';
  }

  return 'right';
}

function normalizeRankedRps(raw = {}) {
  const currentRound = Math.max(
    1,
    Math.min(
      RANKED_RPS_MAX_ROUNDS,
      Math.floor(num(raw.currentRound, 1))
    )
  );

  const rounds = {};

  Object.entries(
    raw.rounds && typeof raw.rounds === 'object'
      ? raw.rounds
      : {}
  ).forEach(([key, value]) => {
    const round = Math.floor(num(key));
    if (
      round < 1 ||
      round > RANKED_RPS_MAX_ROUNDS ||
      !value ||
      typeof value !== 'object'
    ) return;

    rounds[round] = {
      round,
      status: sanitizeId(value.status || 'committing', 30),
      commits:
        value.commits && typeof value.commits === 'object'
          ? value.commits
          : {},
      reveals:
        value.reveals && typeof value.reveals === 'object'
          ? value.reveals
          : {},
      winnerId: sanitizeId(value.winnerId, 96),
      loserId: sanitizeId(value.loserId, 96),
      createdAt: num(value.createdAt),
      resolvedAt: num(value.resolvedAt)
    };
  });

  return {
    version: 1,
    status: sanitizeId(raw.status || 'waiting', 30),
    currentRound,
    firstPlayerId: sanitizeId(raw.firstPlayerId, 96),
    rounds,
    updatedAt: num(raw.updatedAt)
  };
}

function publicRankedRps(match, playerId) {
  const rps = normalizeRankedRps(match?.rps || {});
  const round = rps.rounds[rps.currentRound] || {
    round: rps.currentRound,
    status: 'committing',
    commits: {},
    reveals: {}
  };

  const commits = Object.keys(round.commits || {});
  const reveals = Object.keys(round.reveals || {});
  const resolved = ['resolved', 'draw'].includes(round.status);

  return {
    version: rps.version,
    status: rps.status,
    round: rps.currentRound,
    roundStatus: round.status,
    committed: commits.includes(playerId),
    commits: commits.length,
    revealed: reveals.includes(playerId),
    reveals: reveals.length,
    canReveal:
      commits.length === 2 &&
      !reveals.includes(playerId) &&
      !resolved,
    winnerId: resolved ? round.winnerId : '',
    loserId: resolved ? round.loserId : '',
    firstPlayerId: rps.firstPlayerId,
    choices: resolved
      ? Object.fromEntries(
          Object.entries(round.reveals || {})
            .map(([id, reveal]) => [
              id,
              sanitizeId(reveal?.choice, 20)
            ])
        )
      : {},
    updatedAt: rps.updatedAt
  };
}

function rankedRpsError(message, status = 409) {
  const error = new Error(message);
  error.httpStatus = status;
  return error;
}

async function requireRankedMatchPlayer(
  event,
  body
) {
  const { playerId } = await requirePlayer(event, body);
  const matchId = sanitizeId(body.matchId, 120);

  if (!matchId) {
    throw new Error('ranked_match_required');
  }

  const row = await kvGet(rankedMatchKey(matchId));
  if (!row) throw new Error('ranked_match_not_found');

  const match = payload(row);

  if (!match.participants?.includes(playerId)) {
    throw new Error('ranked_match_forbidden');
  }

  return {
    playerId,
    matchId,
    row,
    match
  };
}

async function actionRankedRpsCommit(event, body) {
  const auth = await requireRankedMatchPlayer(
    event,
    body
  );

  const requestedRound = Math.max(
    1,
    Math.floor(num(body.round, 1))
  );
  const commit = safe(body.commit).toLowerCase();

  if (!/^[a-f0-9]{64}$/.test(commit)) {
    throw new Error('bad_ranked_rps_commit');
  }

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = attempt === 0
      ? auth.row
      : await kvGet(rankedMatchKey(auth.matchId));

    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);

    if (!match.participants?.includes(auth.playerId)) {
      throw new Error('ranked_match_forbidden');
    }

    if (isRankedTerminal(match.status)) {
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(
          match,
          auth.playerId
        )
      };
    }

    if (match.status !== 'pending') {
      throw rankedRpsError(
        'ranked_rps_match_not_pending'
      );
    }

    const escrow = await reconcileEscrowFunding(match);

    if (escrow.status !== 'funded') {
      throw rankedRpsError(
        'ranked_escrow_not_funded'
      );
    }

    const rps = normalizeRankedRps(match.rps);

    if (rps.firstPlayerId) {
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(
          match,
          auth.playerId
        )
      };
    }

    if (requestedRound !== rps.currentRound) {
      throw rankedRpsError(
        'ranked_rps_round_mismatch'
      );
    }

    const current = rps.rounds[requestedRound] || {
      round: requestedRound,
      status: 'committing',
      commits: {},
      reveals: {},
      winnerId: '',
      loserId: '',
      createdAt: now(),
      resolvedAt: 0
    };

    const oldCommit = safe(
      current.commits?.[auth.playerId]
    );

    if (oldCommit) {
      if (oldCommit !== commit) {
        throw rankedRpsError(
          'ranked_rps_commit_conflict'
        );
      }

      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(
          match,
          auth.playerId
        )
      };
    }

    const commits = {
      ...(current.commits || {}),
      [auth.playerId]: commit
    };

    const nextRound = {
      ...current,
      status:
        Object.keys(commits).length === 2
          ? 'revealing'
          : 'committing',
      commits
    };

    const nextRps = {
      ...rps,
      status:
        Object.keys(commits).length === 2
          ? 'revealing'
          : 'committing',
      rounds: {
        ...rps.rounds,
        [requestedRound]: nextRound
      },
      updatedAt: now()
    };

    const next = {
      ...match,
      rps: nextRps,
      updatedAt: now()
    };

    if (!await kvCompareAndPut({
      row,
      type: 'rankedMatch',
      owner: match.roomId,
      expiresAt: num(row.expires_at),
      data: next
    })) {
      continue;
    }

    return {
      ok: true,
      duplicate: false,
      match: publicRankedMatch(
        next,
        auth.playerId
      )
    };
  }

  throw rankedRpsError(
    'ranked_rps_commit_conflict'
  );
}

async function actionRankedRpsReveal(event, body) {
  const auth = await requireRankedMatchPlayer(
    event,
    body
  );

  const requestedRound = Math.max(
    1,
    Math.floor(num(body.round, 1))
  );
  const choice = sanitizeId(body.choice, 20);
  const salt = safe(body.salt).slice(0, 160);

  if (
    !RANKED_RPS_CHOICES.has(choice) ||
    !salt ||
    salt.length < 16
  ) {
    throw new Error('bad_ranked_rps_reveal');
  }

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = attempt === 0
      ? auth.row
      : await kvGet(rankedMatchKey(auth.matchId));

    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);

    if (!match.participants?.includes(auth.playerId)) {
      throw new Error('ranked_match_forbidden');
    }

    if (isRankedTerminal(match.status)) {
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(
          match,
          auth.playerId
        )
      };
    }

    if (match.status !== 'pending') {
      throw rankedRpsError(
        'ranked_rps_match_not_pending'
      );
    }

    const escrow = await reconcileEscrowFunding(match);

    if (escrow.status !== 'funded') {
      throw rankedRpsError(
        'ranked_escrow_not_funded'
      );
    }

    const rps = normalizeRankedRps(match.rps);

    if (rps.firstPlayerId) {
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(
          match,
          auth.playerId
        )
      };
    }

    if (requestedRound !== rps.currentRound) {
      throw rankedRpsError(
        'ranked_rps_round_mismatch'
      );
    }

    const current = rps.rounds[requestedRound];

    if (
      !current ||
      Object.keys(current.commits || {}).length !== 2
    ) {
      throw rankedRpsError(
        'ranked_rps_reveal_not_ready'
      );
    }

    const expectedCommit = rankedRpsCommitHash({
      matchId: auth.matchId,
      round: requestedRound,
      playerId: auth.playerId,
      choice,
      salt
    });

    if (
      safe(current.commits?.[auth.playerId]) !==
      expectedCommit
    ) {
      throw rankedRpsError(
        'ranked_rps_reveal_mismatch'
      );
    }

    const oldReveal = current.reveals?.[auth.playerId];

    if (oldReveal) {
      if (
        oldReveal.choice !== choice ||
        oldReveal.salt !== salt
      ) {
        throw rankedRpsError(
          'ranked_rps_reveal_conflict'
        );
      }

      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(
          match,
          auth.playerId
        )
      };
    }

    const reveals = {
      ...(current.reveals || {}),
      [auth.playerId]: {
        choice,
        salt,
        revealedAt: now()
      }
    };

    let nextRound = {
      ...current,
      status: 'revealing',
      reveals
    };

    let nextRps = {
      ...rps,
      status: 'revealing',
      rounds: {
        ...rps.rounds,
        [requestedRound]: nextRound
      },
      updatedAt: now()
    };

    if (Object.keys(reveals).length === 2) {
      const [leftId, rightId] = match.participants;
      const result = compareRankedRps(
        reveals[leftId].choice,
        reveals[rightId].choice
      );

      if (result === 'draw') {
        if (requestedRound >= RANKED_RPS_MAX_ROUNDS) {
          throw rankedRpsError(
            'ranked_rps_round_limit'
          );
        }

        nextRound = {
          ...nextRound,
          status: 'draw',
          resolvedAt: now()
        };

        nextRps = {
          ...nextRps,
          status: 'committing',
          currentRound: requestedRound + 1,
          rounds: {
            ...nextRps.rounds,
            [requestedRound]: nextRound
          },
          updatedAt: now()
        };
      } else {
        const winnerId =
          result === 'left'
            ? leftId
            : rightId;
        const loserId = otherRankedPlayer(
          match.participants,
          winnerId
        );

        nextRound = {
          ...nextRound,
          status: 'resolved',
          winnerId,
          loserId,
          resolvedAt: now()
        };

        nextRps = {
          ...nextRps,
          status: 'resolved',
          firstPlayerId: winnerId,
          rounds: {
            ...nextRps.rounds,
            [requestedRound]: nextRound
          },
          updatedAt: now()
        };
      }
    }

    const next = {
      ...match,
      rps: nextRps,
      updatedAt: now()
    };

    if (!await kvCompareAndPut({
      row,
      type: 'rankedMatch',
      owner: match.roomId,
      expiresAt: num(row.expires_at),
      data: next
    })) {
      continue;
    }

    return {
      ok: true,
      duplicate: false,
      match: publicRankedMatch(
        next,
        auth.playerId
      )
    };
  }

  throw rankedRpsError(
    'ranked_rps_reveal_conflict'
  );
}

function rankedMatchKey(matchId) {
  return `rankedMatch:${sanitizeId(matchId, 120)}`;
}

function rankedPoint(raw) {
  return {
    x: Math.floor(num(raw?.x, -1)),
    y: Math.floor(num(raw?.y, -1))
  };
}

function rankedPointKey(point) {
  return `${point.x}:${point.y}`;
}

function isRankedPoint(point) {
  return Number.isInteger(point.x) &&
    Number.isInteger(point.y) &&
    point.x >= 0 &&
    point.y >= 0 &&
    point.x < RANKED_BOARD_SIZE &&
    point.y < RANKED_BOARD_SIZE;
}

function normalizeRankedReveal(raw) {
  const points = (Array.isArray(raw?.ships) ? raw.ships : [])
    .map(rankedPoint)
    .filter(isRankedPoint)
    .sort((a, b) => a.y - b.y || a.x - b.x);

  return {
    size: RANKED_BOARD_SIZE,
    ships: points
  };
}

function canonicalRankedReveal(reveal) {
  return JSON.stringify(normalizeRankedReveal(reveal));
}

function collectRankedShips(reveal) {
  const points = normalizeRankedReveal(reveal).ships;
  const all = new Set(points.map(rankedPointKey));
  const seen = new Set();
  const ships = [];

  for (const point of points) {
    const firstKey = rankedPointKey(point);
    if (seen.has(firstKey)) continue;

    const stack = [point];
    const cells = [];

    while (stack.length) {
      const current = stack.pop();
      const key = rankedPointKey(current);

      if (seen.has(key) || !all.has(key)) continue;

      seen.add(key);
      cells.push(current);

      [
        { x: current.x + 1, y: current.y },
        { x: current.x - 1, y: current.y },
        { x: current.x, y: current.y + 1 },
        { x: current.x, y: current.y - 1 }
      ].forEach(next => {
        if (isRankedPoint(next) && all.has(rankedPointKey(next))) {
          stack.push(next);
        }
      });
    }

    ships.push(cells);
  }

  return ships;
}

function validateRankedReveal(reveal) {
  const normalized = normalizeRankedReveal(reveal);
  const pointKeys = normalized.ships.map(rankedPointKey);

  if (num(reveal?.size, RANKED_BOARD_SIZE) !== RANKED_BOARD_SIZE) {
    return { ok: false, reason: 'ranked_bad_board_size' };
  }

  if (
    pointKeys.length !== 20 ||
    new Set(pointKeys).size !== pointKeys.length
  ) {
    return { ok: false, reason: 'ranked_bad_ship_cells' };
  }

  const ships = collectRankedShips(normalized);
  const sizes = ships
    .map(ship => ship.length)
    .sort((a, b) => b - a);

  if (sizes.join(',') !== RANKED_FLEET.join(',')) {
    return {
      ok: false,
      reason: 'ranked_bad_fleet_composition'
    };
  }

  const shipByCell = new Map();

  for (let index = 0; index < ships.length; index++) {
    const ship = ships[index];
    const xs = new Set(ship.map(point => point.x));
    const ys = new Set(ship.map(point => point.y));

    if (xs.size > 1 && ys.size > 1) {
      return {
        ok: false,
        reason: 'ranked_bent_ship'
      };
    }

    const sorted = ship.slice().sort((a, b) =>
      xs.size === 1
        ? a.y - b.y
        : a.x - b.x
    );

    for (let i = 1; i < sorted.length; i++) {
      const previous = sorted[i - 1];
      const current = sorted[i];

      const continuous = xs.size === 1
        ? current.x === previous.x &&
          current.y === previous.y + 1
        : current.y === previous.y &&
          current.x === previous.x + 1;

      if (!continuous) {
        return {
          ok: false,
          reason: 'ranked_ship_has_gap'
        };
      }
    }

    ship.forEach(point => {
      shipByCell.set(rankedPointKey(point), index);
    });
  }

  for (const [key, shipIndex] of shipByCell) {
    const [x, y] = key.split(':').map(Number);

    for (let dy = -1; dy <= 1; dy++) {
      for (let dx = -1; dx <= 1; dx++) {
        if (!dx && !dy) continue;

        const other = shipByCell.get(`${x + dx}:${y + dy}`);
        if (other !== undefined && other !== shipIndex) {
          return { ok: false, reason: 'ranked_ships_touch' };
        }
      }
    }
  }

  return {
    ok: true,
    reveal: normalized,
    ships
  };
}

function normalizeRankedTranscript(raw) {
  if (!Array.isArray(raw) || raw.length > RANKED_MAX_TRANSCRIPT) {
    throw new Error('bad_ranked_transcript');
  }

  return raw.map((item, index) => {
    const sunkCells = (Array.isArray(item?.sunkCells)
      ? item.sunkCells
      : [])
      .map(rankedPoint)
      .filter(isRankedPoint)
      .sort((a, b) => a.y - b.y || a.x - b.x);

    return {
      turn: Math.floor(num(item?.turn, index + 1)),
      shotId: sanitizeId(item?.shotId, 140),
      shooterId: sanitizeId(item?.shooterId, 96),
      x: Math.floor(num(item?.x, -1)),
      y: Math.floor(num(item?.y, -1)),
      result: sanitizeId(item?.result, 20),
      sunkCells
    };
  });
}

function normalizeRankedSubmission(raw, playerId) {
  const submission = raw && typeof raw === 'object' ? raw : {};
  const transcript = normalizeRankedTranscript(submission.transcript);

  const normalized = {
    playerId,
    result: sanitizeId(submission.result, 20),
    firstPlayerId: sanitizeId(submission.firstPlayerId, 96),
    boardReveal: normalizeRankedReveal(submission.boardReveal),
    boardSalt: safe(submission.boardSalt).slice(0, 160),
    boardCommit: safe(submission.boardCommit).slice(0, 128),
    transcript,
    transcriptHash: safe(submission.transcriptHash).slice(0, 128),
    submittedAt: now()
  };

  if (!['win', 'loss'].includes(normalized.result)) {
    throw new Error('bad_ranked_result');
  }

  const actualTranscriptHash = hash(
    stableStringify(normalized.transcript)
  );

  if (
    !normalized.transcriptHash ||
    normalized.transcriptHash !== actualTranscriptHash
  ) {
    throw new Error('bad_ranked_transcript_hash');
  }

  if (
    !normalized.boardSalt ||
    !normalized.boardCommit ||
    !normalized.firstPlayerId
  ) {
    throw new Error('bad_ranked_submission');
  }

  return normalized;
}

function otherRankedPlayer(participants, playerId) {
  return participants.find(id => id !== playerId) || '';
}

function sameRankedCellSet(left, right) {
  const a = new Set((left || []).map(rankedPointKey));
  const b = new Set((right || []).map(rankedPointKey));

  return a.size === b.size &&
    [...a].every(key => b.has(key));
}

function validateRankedTranscript({
  transcript,
  participants,
  firstPlayerId,
  boards
}) {
  if (!transcript.length) {
    return { ok: false, reason: 'ranked_empty_transcript' };
  }

  if (!participants.includes(firstPlayerId)) {
    return { ok: false, reason: 'ranked_bad_first_player' };
  }

  const boardData = new Map();
  const fired = new Map();

  for (const playerId of participants) {
    const check = validateRankedReveal(boards[playerId]);
    if (!check.ok) return check;

    boardData.set(playerId, {
      points: new Set(check.reveal.ships.map(rankedPointKey)),
      ships: check.ships
    });
    fired.set(playerId, new Set());
  }

  let expectedShooter = firstPlayerId;
  let winnerId = '';

  for (let index = 0; index < transcript.length; index++) {
    const event = transcript[index];

    if (event.turn !== index + 1) {
      return { ok: false, reason: 'ranked_turn_sequence_invalid' };
    }

    if (
      !event.shotId ||
      event.shooterId !== expectedShooter ||
      !participants.includes(event.shooterId) ||
      !isRankedPoint(event) ||
      !['miss', 'hit', 'sunk'].includes(event.result)
    ) {
      return { ok: false, reason: 'ranked_shot_invalid' };
    }

    const targetId = otherRankedPlayer(
      participants,
      event.shooterId
    );
    const targetBoard = boardData.get(targetId);
    const shooterShots = fired.get(event.shooterId);
    const shotKey = rankedPointKey(event);

    if (shooterShots.has(shotKey)) {
      return { ok: false, reason: 'ranked_duplicate_shot' };
    }

    const hasShip = targetBoard.points.has(shotKey);
    shooterShots.add(shotKey);

    let expectedResult = 'miss';
    let expectedSunkCells = [];

    if (hasShip) {
      const ship = targetBoard.ships.find(cells =>
        cells.some(point => rankedPointKey(point) === shotKey)
      ) || [];

      const sunk = ship.length > 0 && ship.every(point =>
        shooterShots.has(rankedPointKey(point))
      );

      expectedResult = sunk ? 'sunk' : 'hit';
      expectedSunkCells = sunk ? ship : [];
    }

    if (event.result !== expectedResult) {
      return {
        ok: false,
        reason: 'ranked_shot_result_mismatch'
      };
    }

    if (
      expectedResult === 'sunk' &&
      !sameRankedCellSet(event.sunkCells, expectedSunkCells)
    ) {
      return {
        ok: false,
        reason: 'ranked_sunk_cells_mismatch'
      };
    }

    const targetDefeated = [...targetBoard.points]
      .every(key => shooterShots.has(key));

    if (targetDefeated) {
      if (index !== transcript.length - 1) {
        return {
          ok: false,
          reason: 'ranked_transcript_after_finish'
        };
      }

      winnerId = event.shooterId;
      break;
    }

    expectedShooter = event.result === 'miss'
      ? targetId
      : event.shooterId;
  }

  if (!winnerId) {
    return { ok: false, reason: 'ranked_match_not_finished' };
  }

  return {
    ok: true,
    winnerId,
    loserId: otherRankedPlayer(participants, winnerId),
    turns: transcript.length
  };
}

function validateRankedSubmissions(match) {
  const participants = Array.isArray(match.participants)
    ? match.participants
    : [];

  if (participants.length !== 2 || new Set(participants).size !== 2) {
    return { ok: false, reason: 'ranked_participants_invalid' };
  }

  const left = match.submissions?.[participants[0]];
  const right = match.submissions?.[participants[1]];

  if (!left || !right) {
    return { ok: false, reason: 'ranked_submissions_pending' };
  }

  const serverFirstPlayerId = sanitizeId(
    match.rps?.firstPlayerId,
    96
  );

  if (
    !serverFirstPlayerId ||
    left.firstPlayerId !== serverFirstPlayerId ||
    right.firstPlayerId !== serverFirstPlayerId ||
    left.transcriptHash !== right.transcriptHash ||
    stableStringify(left.transcript) !== stableStringify(right.transcript)
  ) {
    return { ok: false, reason: 'ranked_transcripts_disagree' };
  }

  if (left.result === right.result) {
    return { ok: false, reason: 'ranked_results_disagree' };
  }

  for (const submission of [left, right]) {
    const layout = validateRankedReveal(submission.boardReveal);
    if (!layout.ok) return layout;

    const expectedCommit = hash(
      `${submission.boardSalt}:${canonicalRankedReveal(submission.boardReveal)}`
    );

    if (expectedCommit !== submission.boardCommit) {
      return { ok: false, reason: 'ranked_board_commit_mismatch' };
    }
  }

  const transcriptCheck = validateRankedTranscript({
    transcript: left.transcript,
    participants,
    firstPlayerId: left.firstPlayerId,
    boards: {
      [participants[0]]: left.boardReveal,
      [participants[1]]: right.boardReveal
    }
  });

  if (!transcriptCheck.ok) return transcriptCheck;

  if (
    match.submissions[transcriptCheck.winnerId]?.result !== 'win' ||
    match.submissions[transcriptCheck.loserId]?.result !== 'loss'
  ) {
    return { ok: false, reason: 'ranked_winner_result_mismatch' };
  }

  return transcriptCheck;
}

async function buildRankedSettlementPlan({
  match,
  winnerId,
  loserId,
  outcome = 'completed',
  turns = 0
}) {
  if (
    !match?.participants?.includes(winnerId) ||
    !match?.participants?.includes(loserId) ||
    winnerId === loserId
  ) {
    throw new Error('ranked_settlement_players_invalid');
  }

  const [winnerProfile, loserProfile] = await Promise.all([
    kvGet(`profile:${winnerId}`),
    kvGet(`profile:${loserId}`)
  ]);

  if (!winnerProfile || !loserProfile) {
    throw new Error('ranked_profile_not_found');
  }

  const winnerRating = Math.max(
    100,
    num(payload(winnerProfile).rating, 1000)
  );
  const loserRating = Math.max(
    100,
    num(payload(loserProfile).rating, 1000)
  );

  const expected = 1 / (
    1 + Math.pow(10, (loserRating - winnerRating) / 400)
  );

  const winnerDelta = Math.max(
    1,
    Math.round(24 * (1 - expected))
  );

  return {
    id: `settlement:${match.matchId}`,
    outcome,
    winnerId,
    loserId,
    winnerDelta,
    loserDelta: -winnerDelta,
    turns: Math.max(0, num(turns)),
    economy: {
      required: match.economy?.required === true,
      status: safe(
        match.economy?.status ||
        'locking'
      ),
      stakeEach: Math.max(
        0,
        Math.floor(num(
          match.economy?.stakeEach,
          RANKED_STAKE_AMOUNT
        ))
      ),
      escrow: Math.max(
        0,
        Math.floor(num(
          match.economy?.escrow,
          RANKED_STAKE_AMOUNT * 2
        ))
      )
    },
    createdAt: now()
  };
}

async function applyRankedProfileSettlement({
  playerId,
  matchId,
  won,
  delta
}) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await kvGet(`profile:${playerId}`);
    if (!row) throw new Error('ranked_profile_not_found');

    const profile = payload(row);
    const settled = Array.isArray(profile.rankedSettlements)
      ? profile.rankedSettlements.map(value => sanitizeId(value, 120))
      : [];

    const currentRating = Math.max(
      100,
      num(profile.rating, 1000)
    );

    const matches = Math.max(
      num(profile.rankedMatches),
      num(profile.matches)
    );

    if (settled.includes(matchId)) {
      return {
        ok: true,
        duplicate: true,
        rating: currentRating,
        matches
      };
    }

    const next = {
      ...profile,
      rating: Math.max(100, Math.min(3000, currentRating + delta)),
      rankedMatches: matches + 1,
      rankedWins: Math.max(
        num(profile.rankedWins),
        num(profile.wins)
      ) + (won ? 1 : 0),
      rankedLosses: Math.max(
        num(profile.rankedLosses),
        num(profile.losses)
      ) + (won ? 0 : 1),
      rankedV2: true,
      rankedUpdatedAt: now(),
      rankedSettlements: [...settled, matchId]
        .slice(-RANKED_SETTLEMENT_HISTORY)
    };

    const changed = await kvCompareAndPut({
      row,
      type: 'profile',
      owner: playerId,
      data: next
    });

    if (changed) {
      return {
        ok: true,
        rating: next.rating,
        matches: next.rankedMatches
      };
    }
  }

  throw new Error('ranked_profile_settlement_conflict');
}

async function settleRankedMatch(matchId) {
  const key = rankedMatchKey(matchId);

  for (let attempt = 0; attempt < 10; attempt++) {
    const row = await kvGet(key);
    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);

    if (isRankedTerminal(match.status)) {
      return reconcileRankedEconomy(match);
    }

    if (match.status === 'pending') {
      if (Object.keys(match.submissions || {}).length < 2) {
        return match;
      }

      const check = validateRankedSubmissions(match);

      if (!check.ok) {
        const disputed = transitionRankedMatch(
          match,
          'disputed',
          {
            reason: check.reason,
            extra: {
              validation: check
            }
          }
        );

        if (await kvCompareAndPut({
          row,
          type: 'rankedMatch',
          owner: match.roomId,
          expiresAt: num(row.expires_at),
          data: disputed
        })) {
          return reconcileRankedEconomy(disputed);
        }

        continue;
      }

      const settlement = await buildRankedSettlementPlan({
        match,
        winnerId: check.winnerId,
        loserId: check.loserId,
        outcome: 'completed',
        turns: check.turns
      });

      const settling = transitionRankedMatch(
        match,
        'settling',
        {
          reason: 'validated',
          extra: {
            validation: check,
            settlement
          }
        }
      );

      if (!await kvCompareAndPut({
        row,
        type: 'rankedMatch',
        owner: match.roomId,
        expiresAt: num(row.expires_at),
        data: settling
      })) {
        continue;
      }

      continue;
    }

    if (match.status === 'forfeit_pending') {
      const forfeit = match.forfeit || {};

      if (
        num(forfeit.deadlineAt) > now() ||
        !match.participants?.includes(forfeit.loserId)
      ) {
        return match;
      }

      const loserId = forfeit.loserId;
      const winnerId = otherRankedPlayer(
        match.participants,
        loserId
      );

      const settlement = await buildRankedSettlementPlan({
        match,
        winnerId,
        loserId,
        outcome: 'forfeit',
        turns: 0
      });

      const settling = transitionRankedMatch(
        match,
        'settling',
        {
          reason: forfeit.reason || 'forfeit',
          actorId: loserId,
          extra: {
            validation: {
              ok: true,
              reason: 'server_issued_forfeit',
              winnerId,
              loserId,
              turns: 0
            },
            settlement
          }
        }
      );

      if (!await kvCompareAndPut({
        row,
        type: 'rankedMatch',
        owner: match.roomId,
        expiresAt: num(row.expires_at),
        data: settling
      })) {
        continue;
      }

      continue;
    }

    if (match.status !== 'settling') {
      return match;
    }

    const settlement = match.settlement;

    if (!settlement?.winnerId || !settlement?.loserId) {
      const disputed = transitionRankedMatch(
        match,
        'disputed',
        {
          reason: 'ranked_settlement_plan_missing'
        }
      );

      if (await kvCompareAndPut({
        row,
        type: 'rankedMatch',
        owner: match.roomId,
        expiresAt: num(row.expires_at),
        data: disputed
      })) {
        return disputed;
      }

      continue;
    }

    const [winner, loser] = await Promise.all([
      applyRankedProfileSettlement({
        playerId: settlement.winnerId,
        matchId,
        won: true,
        delta: num(settlement.winnerDelta)
      }),
      applyRankedProfileSettlement({
        playerId: settlement.loserId,
        matchId,
        won: false,
        delta: num(settlement.loserDelta)
      })
    ]);

    const terminalStatus =
      settlement.outcome === 'forfeit'
        ? 'forfeited'
        : 'settled';

    const completed = transitionRankedMatch(
      match,
      terminalStatus,
      {
        reason:
          settlement.outcome === 'forfeit'
            ? 'server_issued_forfeit'
            : 'settled',
        actorId:
          settlement.outcome === 'forfeit'
            ? settlement.loserId
            : '',
        extra: {
          settlement: {
            ...settlement,
            winnerRating: winner.rating || 0,
            loserRating: loser.rating || 0,
            settledAt: now()
          },
          settledAt: now()
        }
      }
    );

    if (await kvCompareAndPut({
      row,
      type: 'rankedMatch',
      owner: match.roomId,
      expiresAt: num(row.expires_at),
      data: completed
    })) {
      return reconcileRankedEconomy(completed);
    }
  }

  throw new Error('ranked_settlement_conflict');
}

async function reconcileRankedMatch(matchId) {
  const key = rankedMatchKey(matchId);

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await kvGet(key);
    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);

    if (
      isRankedTerminal(match.status) ||
      match.status === 'settling'
    ) {
      return match.status === 'settling'
        ? settleRankedMatch(matchId)
        : reconcileRankedEconomy(match);
    }

    if (match.status === 'forfeit_pending') {
      return num(match.forfeit?.deadlineAt) <= now()
        ? settleRankedMatch(matchId)
        : match;
    }

    if (match.status !== 'pending') return match;

    const submissions = Object.values(
      match.submissions || {}
    );
    const age = now() - num(match.createdAt);

    if (submissions.length === 1) {
      const submittedAt = num(
        submissions[0]?.submittedAt
      );

      if (
        submittedAt > 0 &&
        now() - submittedAt >=
          RANKED_SUBMISSION_TIMEOUT_MS
      ) {
        const disputed = transitionRankedMatch(
          match,
          'disputed',
          {
            reason: 'ranked_peer_submission_timeout',
            extra: {
              validation: {
                ok: false,
                reason: 'ranked_peer_submission_timeout'
              }
            }
          }
        );

        if (await kvCompareAndPut({
          row,
          type: 'rankedMatch',
          owner: match.roomId,
          expiresAt: num(row.expires_at),
          data: disputed
        })) {
          return reconcileRankedEconomy(disputed);
        }

        continue;
      }
    }

    if (
      submissions.length === 0 &&
      age >= RANKED_ABANDONED_TIMEOUT_MS
    ) {
      const aborted = transitionRankedMatch(
        match,
        'aborted',
        {
          reason: 'ranked_abandoned'
        }
      );

      if (await kvCompareAndPut({
        row,
        type: 'rankedMatch',
        owner: match.roomId,
        expiresAt: num(row.expires_at),
        data: aborted
      })) {
        return reconcileRankedEconomy(aborted);
      }

      continue;
    }

    return match;
  }

  throw new Error('ranked_reconcile_conflict');
}

function publicRankedMatch(match, playerId) {
  return {
    matchId: match.matchId,
    roomId: match.roomId,
    gameId: match.gameId,
    status: match.status,
    terminal: isRankedTerminal(match.status),
    terminalReason: safe(match.terminalReason || ''),
    terminalActorId: safe(match.terminalActorId || ''),
    participants: match.participants,
    submitted: !!match.submissions?.[playerId],
    submissions: Object.keys(match.submissions || {}).length,
    validation: match.validation || null,
    settlement: match.settlement || null,
    rps: publicRankedRps(match, playerId),
    forfeit: match.forfeit
      ? {
          loserId: match.forfeit.loserId,
          reason: match.forfeit.reason,
          requestedAt: num(match.forfeit.requestedAt),
          deadlineAt: num(match.forfeit.deadlineAt)
        }
      : null,
    economy: match.economy || {
      required: false,
      status: 'not_required'
    },
    createdAt: num(match.createdAt),
    updatedAt: num(match.updatedAt),
    terminalAt: num(match.terminalAt),
    settledAt: num(match.settledAt),
    refundedAt: num(match.refundedAt)
  };
}

async function actionRankedMatchPrepare(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const roomId = sanitizeId(body.roomId);
  const roomSecret = safe(body.roomSecret);
  const roomRow = roomId ? await kvGet(`room:${roomId}`) : null;
  const room = payload(roomRow);

  if (!roomRow || room.roomSecretHash !== hash(roomSecret)) {
    return { ok: false, reason: 'room_not_found' };
  }

  if (
    room.gameId !== RANKED_GAME_ID ||
    room.ranked !== true ||
    room.matchMode !== 'ranked'
  ) {
    return { ok: false, reason: 'ranked_room_required' };
  }

  if (!isRoomParticipant(room, playerId)) {
    return { ok: false, reason: 'room_forbidden' };
  }

  const participants = [
    sanitizeId(room.hostPlayerId),
    sanitizeId(room.guestPlayerId)
  ].filter(Boolean);

  if (participants.length !== 2 || new Set(participants).size !== 2) {
    return { ok: false, reason: 'ranked_two_players_required' };
  }

  let matchId = '';

  for (let attempt = 0; attempt < 8; attempt++) {
    const currentRoomRow = attempt === 0
      ? roomRow
      : await kvGet(`room:${roomId}`);

    if (!currentRoomRow) {
      throw new Error('room_not_found');
    }

    const currentRoom = payload(currentRoomRow);
    const currentMatchId = sanitizeId(
      currentRoom.rankedMatchId,
      120
    );

    const currentMatchRow = currentMatchId
      ? await kvGet(rankedMatchKey(currentMatchId))
      : null;

    const currentMatch = payload(currentMatchRow);
    const terminal = isRankedTerminal(
      currentMatch.status
    );

    if (
      currentMatchRow &&
      !terminal
    ) {
      matchId = currentMatchId;
      break;
    }

    const candidate = rid('ranked');
    const preparedAt = now();

    const changed = await kvCompareAndPut({
      row: currentRoomRow,
      type: 'room',
      owner: currentRoom.hostPlayerId,
      expiresAt: num(currentRoomRow.expires_at),
      data: {
        ...currentRoom,
        rankedMatchId: candidate,
        rankedPreparedAt: preparedAt,
        updatedAt: preparedAt
      }
    });

    if (!changed) continue;

    await kvPut({
      pk: rankedMatchKey(candidate),
      type: 'rankedMatch',
      owner: roomId,
      expiresAt:
        num(currentRoom.reconnectUntil) ||
        preparedAt + CFG.roomTtlMs,
      data: {
        version: 2,
        matchId: candidate,
        roomId,
        gameId: RANKED_GAME_ID,
        participants,
        status: 'pending',
        rps: {
          version: 1,
          status: 'waiting',
          currentRound: 1,
          firstPlayerId: '',
          rounds: {},
          updatedAt: preparedAt
        },
        submissions: {},
        economy: {
          required: true,
          status: 'locking',
          stakeEach: RANKED_STAKE_AMOUNT,
          escrow: RANKED_STAKE_AMOUNT * 2,
          lockedPlayers: 0,
          participants: 2,
          fundedAt: 0,
          paidAt: 0,
          refundedAt: 0,
          updatedAt: preparedAt
        },
        createdAt: preparedAt,
        updatedAt: preparedAt
      }
    });

    matchId = candidate;
    break;
  }

  if (!matchId) {
    throw new Error('ranked_match_prepare_conflict');
  }

  const matchRow = await kvGet(
    rankedMatchKey(matchId)
  );
  const match = payload(matchRow);

  if (!matchRow) {
    throw new Error('ranked_match_not_ready');
  }

  await getOrCreateRankedEscrow(match);

  return {
    ok: true,
    playerId,
    peerPlayerId: otherRankedPlayer(participants, playerId),
    match: publicRankedMatch(match, playerId)
  };
}

async function actionRankedMatchSubmit(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const matchId = sanitizeId(body.matchId, 120);
  const key = rankedMatchKey(matchId);

  if (!matchId) throw new Error('ranked_match_required');

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await kvGet(key);
    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);

    if (!match.participants?.includes(playerId)) {
      throw new Error('ranked_match_forbidden');
    }

    if (isRankedTerminal(match.status)) {
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(match, playerId)
      };
    }

    if (match.status !== 'pending') {
      throw rankedRpsError(
        'ranked_submission_match_not_pending'
      );
    }

    if (!sanitizeId(match.rps?.firstPlayerId, 96)) {
      throw rankedRpsError(
        'ranked_rps_not_resolved'
      );
    }

    const submission = normalizeRankedSubmission(
      body.submission || body,
      playerId
    );
    const old = match.submissions?.[playerId];

    if (old) {
      if (
        old.transcriptHash !== submission.transcriptHash ||
        old.boardCommit !== submission.boardCommit ||
        old.result !== submission.result
      ) {
        throw new Error('ranked_submission_conflict');
      }

      const settled = await settleRankedMatch(matchId);
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(settled, playerId)
      };
    }

    const next = {
      ...match,
      submissions: {
        ...(match.submissions || {}),
        [playerId]: submission
      },
      updatedAt: now()
    };

    if (!await kvCompareAndPut({
      row,
      type: 'rankedMatch',
      owner: match.roomId,
      expiresAt: num(row.expires_at),
      data: next
    })) {
      continue;
    }

    const settled = await settleRankedMatch(matchId);

    return {
      ok: true,
      duplicate: false,
      match: publicRankedMatch(settled, playerId)
    };
  }

  throw new Error('ranked_submission_conflict');
}
async function actionRankedMatchAbort(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const matchId = sanitizeId(body.matchId, 120);
  const reason = sanitizeId(
    body.reason || 'disconnect',
    80
  );

  if (!matchId) throw new Error('ranked_match_required');

  const key = rankedMatchKey(matchId);

  for (let attempt = 0; attempt < 8; attempt++) {
    const row = await kvGet(key);
    if (!row) throw new Error('ranked_match_not_found');

    const match = payload(row);

    if (!match.participants?.includes(playerId)) {
      throw new Error('ranked_match_forbidden');
    }

    if (isRankedTerminal(match.status)) {
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(match, playerId)
      };
    }

    if (match.status === 'settling') {
      const current = await settleRankedMatch(matchId);
      return {
        ok: true,
        duplicate: true,
        match: publicRankedMatch(current, playerId)
      };
    }

    const explicit = [
      'surrender',
      'user_exit'
    ].includes(reason);

    const requestedAt = now();
    const deadlineAt = explicit
      ? requestedAt
      : requestedAt + RANKED_FORFEIT_GRACE_MS;

    const next = transitionRankedMatch(
      match,
      'forfeit_pending',
      {
        reason,
        actorId: playerId,
        extra: {
          forfeit: {
            loserId: playerId,
            winnerId: otherRankedPlayer(
              match.participants,
              playerId
            ),
            reason,
            explicit,
            requestedAt,
            deadlineAt
          }
        }
      }
    );

    if (!await kvCompareAndPut({
      row,
      type: 'rankedMatch',
      owner: match.roomId,
      expiresAt: num(row.expires_at),
      data: next
    })) {
      continue;
    }

    const current = explicit
      ? await settleRankedMatch(matchId)
      : next;

    return {
      ok: true,
      duplicate: false,
      match: publicRankedMatch(current, playerId)
    };
  }

  throw new Error('ranked_abort_conflict');
}

async function actionRankedMatchCleanup(event, body) {
  const admin = headerValue(event, 'x-vi3-admin') ||
    safe(body.adminSecret);

  if (
    !CFG.adminSecret ||
    !timingSafeEqualText(admin, CFG.adminSecret)
  ) {
    throw new Error('bad_admin_secret');
  }

  const rows = await kvPrefix('rankedMatch:', 500);
  const results = [];

  for (const row of rows) {
    const match = payload(row);

    const economyDone = [
      'paid',
      'refunded',
      'not_required'
    ].includes(match.economy?.status);

    if (
      !match.matchId ||
      (
        isRankedTerminal(match.status) &&
        economyDone
      )
    ) {
      continue;
    }

    try {
      const current = isRankedTerminal(match.status)
        ? await reconcileRankedEconomy(match)
        : await reconcileRankedMatch(match.matchId);

      if (current.status !== match.status) {
        results.push({
          matchId: match.matchId,
          from: match.status,
          to: current.status
        });
      }
    } catch (error) {
      results.push({
        matchId: match.matchId,
        from: match.status,
        to: 'error',
        error: safe(error?.message)
      });
    }
  }

  return {
    ok: true,
    scanned: rows.length,
    changed: results.length,
    results
  };
}
async function actionRankedMatchStatus(event, body) {
  const { playerId } = await requirePlayer(event, body);
  const matchId = sanitizeId(body.matchId, 120);
  const row = matchId
    ? await kvGet(rankedMatchKey(matchId))
    : null;
  const match = payload(row);

  if (!row) throw new Error('ranked_match_not_found');

  if (!match.participants?.includes(playerId)) {
    throw new Error('ranked_match_forbidden');
  }

  const current = await reconcileRankedMatch(matchId);

  return {
    ok: true,
    match: publicRankedMatch(current, playerId)
  };
}

async function actionLeaderboardV2Get(event, body) {
  await requirePlayer(event, body);

  const rows = await kvPrefix('profile:', 1000);
  const leaders = rows
    .map(payload)
    .filter(profile => num(profile.rankedMatches) > 0)
    .sort((a, b) =>
      num(b.rating, 1000) - num(a.rating, 1000) ||
      num(b.rankedWins) - num(a.rankedWins)
    )
    .slice(0, 50)
    .map(profile => ({
      playerId: profile.friendId,
      displayName: profile.displayName,
      avatarUrl: profile.avatarUrl,
      rating: num(profile.rating, 1000),
      wins: num(profile.rankedWins),
      losses: num(profile.rankedLosses),
      matches: num(profile.rankedMatches)
    }));

  return {
    ok: true,
    version: 2,
    legacyFrozen: false,
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
  room_join_token_create: actionRoomJoinTokenCreate,
  room_join_token_redeem: actionRoomJoinTokenRedeem,
  room_get: actionRoomGet,
  room_close: actionRoomClose,
  room_set_mode: actionRoomSetMode,
  signal_send: actionSignalSend,
  signal_poll: actionSignalPoll,
  ranked_match_prepare: actionRankedMatchPrepare,
  ranked_stake_prepare: actionRankedStakePrepare,
  ranked_rps_commit: actionRankedRpsCommit,
  ranked_rps_reveal: actionRankedRpsReveal,
  ranked_match_submit: actionRankedMatchSubmit,
  ranked_match_status: actionRankedMatchStatus,
  ranked_match_abort: actionRankedMatchAbort,
  ranked_match_cleanup: actionRankedMatchCleanup,
  leaderboard_v2_get: actionLeaderboardV2Get,
  wallet_get: actionWalletGet,
  wallet_registration_backfill:
    actionWalletRegistrationBackfill,
  wallet_purchase_avatar: actionWalletPurchaseAvatar,
  favorite_state_get: actionFavoriteStateGet,
  favorite_state_mutate: actionFavoriteStateMutate,
  favorite_state_reconcile:
    actionFavoriteStateReconcile,
  listen_session_start: actionListenSessionStart,
  listen_session_heartbeat: actionListenSessionHeartbeat,
  listen_session_complete: actionListenSessionComplete,
  achievement_reward_status:
    actionAchievementRewardStatus,
  backup_achievement_receipt:
    actionBackupAchievementReceipt,
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
        listeningReceipts: {
          enabled: true,
          shadow: CFG.listeningReceiptsShadow,
          catalogConfigured:
            LISTEN_TRACK_CATALOG.size > 0,
          catalogTracks:
            LISTEN_TRACK_CATALOG.size,
          heartbeatMinMs:
            CFG.listenHeartbeatMinMs,
          heartbeatMaxGapMs:
            CFG.listenHeartbeatMaxGapMs,
          backgroundMaxGapMs:
            CFG.listenBackgroundMaxGapMs,
          sessionMaxMs:
            CFG.listenSessionMaxMs
        },
        favoriteMirror: {
          enabled: true,
          rewardsShadow:
            CFG.favoriteRewardsShadow,
          catalogTracks:
            LISTEN_TRACK_CATALOG.size
        },
        backupRewards: {
          enabled: true,
          shadow: CFG.backupRewardsShadow,
          receiptSecretConfigured:
            !!CFG.backupReceiptSecret
        },
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
        /listen_session_expired/i.test(msg)
      ) {
        status = 410;
      } else if (
        /listen_session_not_found/i.test(msg)
      ) {
        status = 404;
      } else if (
        /listen_session_(not_active|not_completable)|chat_revision_conflict|ranked_.*conflict|crypto_.*(?:missing|not_ready|conflict)|chat_e2ee_disabled/i.test(msg)
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
