const MAX_PHOTO_SIZE = 20 * 1024 * 1024;
const INVITE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const encoder = new TextEncoder();

function corsHeaders(env) {
    return {
        'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };
}

function jsonResponse(env, body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            ...corsHeaders(env),
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store'
        }
    });
}

async function readJson(request) {
    try {
        return await request.json();
    } catch (error) {
        return null;
    }
}

function randomInviteCode() {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    return Array.from(bytes, byte => INVITE_ALPHABET[byte & 31]).join('');
}

function encodeBase64Url(bytes) {
    let binary = '';
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
    return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function getSessionKey(secret) {
    return crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
    );
}

async function createAdminToken(env) {
    const payload = encodeBase64Url(encoder.encode(JSON.stringify({
        expiresAt: Date.now() + 8 * 60 * 60 * 1000
    })));
    const signature = await crypto.subtle.sign(
        'HMAC',
        await getSessionKey(env.ADMIN_SESSION_SECRET),
        encoder.encode(payload)
    );
    return `${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

async function isAdminRequest(request, env) {
    if (!env.ADMIN_SESSION_SECRET) {
        return false;
    }
    const authorization = request.headers.get('Authorization') || '';
    const match = /^Bearer ([A-Za-z0-9._-]+)$/.exec(authorization);
    if (!match) {
        return false;
    }
    const [payload, signature, extra] = match[1].split('.');
    if (!payload || !signature || extra) {
        return false;
    }
    try {
        const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)));
        if (!Number.isFinite(claims.expiresAt) || claims.expiresAt <= Date.now()) {
            return false;
        }
        return await crypto.subtle.verify(
            'HMAC',
            await getSessionKey(env.ADMIN_SESSION_SECRET),
            decodeBase64Url(signature),
            encoder.encode(payload)
        );
    } catch (error) {
        return false;
    }
}

function validName(value) {
    return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= 160;
}

function validInviteCode(value) {
    return typeof value === 'string' && /^[A-HJ-NP-Z2-9]{8}$/.test(value);
}

async function withinRateLimit(env, request, action, maximum, windowMs) {
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const digest = await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(`${action}:${clientIp}`)
    );
    const keyHash = encodeBase64Url(new Uint8Array(digest));
    const windowStarted = Math.floor(Date.now() / windowMs) * windowMs;
    const result = await env.DB.prepare(
        `INSERT INTO api_rate_limits (key_hash, window_started, request_count)
         VALUES (?, ?, 1)
         ON CONFLICT(key_hash) DO UPDATE SET
             request_count = CASE
                 WHEN api_rate_limits.window_started = excluded.window_started
                 THEN api_rate_limits.request_count + 1
                 ELSE 1
             END,
             window_started = excluded.window_started
         RETURNING request_count`
    ).bind(keyHash, windowStarted).first();
    return result.request_count <= maximum;
}

async function createGuest(env, name, sourceKey = null) {
    for (let attempt = 0; attempt < 5; attempt++) {
        const guest = {
            id: crypto.randomUUID(),
            name: name.trim(),
            invite_code: randomInviteCode(),
            created_at: new Date().toISOString()
        };
        try {
            await env.DB.prepare(
                'INSERT INTO guests (id, name, invite_code, created_at, source_key) VALUES (?, ?, ?, ?, ?)'
            ).bind(guest.id, guest.name, guest.invite_code, guest.created_at, sourceKey).run();
            return guest;
        } catch (error) {
            if (!String(error.message).includes('UNIQUE constraint failed: guests.invite_code')) {
                throw error;
            }
        }
    }
    throw new Error('Could not generate a unique invitation code.');
}

async function handlePublicWishes(request, url, env) {
    if (!env.DB) {
        return jsonResponse(env, { error: 'The guest database is not configured.' }, 503);
    }
    if (!await withinRateLimit(env, request, 'public-wishes', 120, 10 * 60 * 1000)) {
        return jsonResponse(env, { error: 'Too many wish requests. Please wait and try again.' }, 429);
    }
    if (request.method === 'GET') {
        const code = url.searchParams.get('code') || '';
        if (!validInviteCode(code)) {
            return jsonResponse(env, { error: 'A valid invitation code is required.' }, 400);
        }
        const guest = await env.DB.prepare(
            'SELECT id, name FROM guests WHERE invite_code = ?'
        ).bind(code).first();
        if (!guest) {
            return jsonResponse(env, { error: 'This invitation link is not valid.' }, 404);
        }
        const wish = await env.DB.prepare(
            'SELECT message, updated_at FROM wishes WHERE guest_id = ?'
        ).bind(guest.id).first();
        return jsonResponse(env, { guest: { name: guest.name }, wish: wish || null });
    }
    if (request.method === 'POST') {
        const body = await readJson(request);
        if (!body || !validInviteCode(body.code) || typeof body.message !== 'string') {
            return jsonResponse(env, { error: 'A valid invitation code and wish are required.' }, 400);
        }
        const message = body.message.trim();
        if (!message || message.length > 2000) {
            return jsonResponse(env, { error: 'A wish must contain 1 to 2000 characters.' }, 400);
        }
        const guest = await env.DB.prepare(
            'SELECT id FROM guests WHERE invite_code = ?'
        ).bind(body.code).first();
        if (!guest) {
            return jsonResponse(env, { error: 'This invitation link is not valid.' }, 404);
        }
        const updatedAt = new Date().toISOString();
        await env.DB.prepare(
            `INSERT INTO wishes (guest_id, message, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(guest_id) DO UPDATE SET
                 message = excluded.message,
                 updated_at = excluded.updated_at`
        ).bind(guest.id, message, updatedAt).run();
        return jsonResponse(env, { success: true, updatedAt });
    }
    return jsonResponse(env, { error: 'Method not allowed.' }, 405);
}

async function handleAdminApi(request, url, env) {
    if (!env.DB) {
        return jsonResponse(env, { error: 'The guest database is not configured.' }, 503);
    }
    if (!env.ADMIN_PASSWORD || !env.ADMIN_SESSION_SECRET) {
        return jsonResponse(env, { error: 'Dashboard authentication is not configured.' }, 503);
    }

    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (path === '/api/admin/login' && request.method === 'POST') {
        if (!await withinRateLimit(env, request, 'admin-login', 8, 15 * 60 * 1000)) {
            return jsonResponse(env, { error: 'Too many sign-in attempts. Please wait 15 minutes.' }, 429);
        }
        const body = await readJson(request);
        if (typeof body?.password !== 'string' || body.password.length > 256 || body.password !== env.ADMIN_PASSWORD) {
            return jsonResponse(env, { error: 'Invalid password.' }, 401);
        }
        return jsonResponse(env, { token: await createAdminToken(env) });
    }

    if (!await isAdminRequest(request, env)) {
        return jsonResponse(env, { error: 'Dashboard session expired. Please log in again.' }, 401);
    }

    if (path === '/api/admin/dashboard' && request.method === 'GET') {
        const [guests, wishes, photos] = await Promise.all([
            env.DB.prepare('SELECT COUNT(*) AS total FROM guests').first(),
            env.DB.prepare('SELECT COUNT(*) AS total FROM wishes').first(),
            env.DB.prepare("SELECT COUNT(*) AS total FROM photos WHERE telegram_status = 'sent'").first()
        ]);
        return jsonResponse(env, {
            totalGuests: guests.total,
            totalWishes: wishes.total,
            totalPhotos: photos.total
        });
    }

    if (path === '/api/admin/guests' && request.method === 'GET') {
        const { results } = await env.DB.prepare(
            'SELECT id, name, invite_code, created_at FROM guests ORDER BY name COLLATE NOCASE'
        ).all();
        return jsonResponse(env, { guests: results });
    }

    if (path === '/api/admin/guests' && request.method === 'POST') {
        const body = await readJson(request);
        if (!validName(body?.name)) {
            return jsonResponse(env, { error: 'Guest name must contain 1 to 160 characters.' }, 400);
        }
        const guest = await createGuest(env, body.name);
        return jsonResponse(env, { guest }, 201);
    }

    if (path === '/api/admin/guests/import' && request.method === 'POST') {
        const body = await readJson(request);
        if (!Array.isArray(body?.guests) || body.guests.length > 500) {
            return jsonResponse(env, { error: 'Provide a list of up to 500 guests to import.' }, 400);
        }
        const imported = [];
        let skipped = 0;
        for (const item of body.guests) {
            if (!validName(item?.name) || typeof item.sourceId !== 'string'
                || !/^[a-zA-Z0-9_-]{1,64}$/.test(item.sourceId)) {
                return jsonResponse(env, { error: 'An imported guest has an invalid name or source ID.' }, 400);
            }
            const sourceKey = `legacy:${item.sourceId}`;
            const existing = await env.DB.prepare(
                'SELECT id FROM guests WHERE source_key = ?'
            ).bind(sourceKey).first();
            if (existing) {
                skipped++;
                continue;
            }
            imported.push(await createGuest(env, item.name, sourceKey));
        }
        return jsonResponse(env, { imported, skipped }, 201);
    }

    const guestMatch = /^\/api\/admin\/guests\/([0-9a-f-]{36})$/i.exec(path);
    if (guestMatch && request.method === 'PUT') {
        const body = await readJson(request);
        if (!validName(body?.name)) {
            return jsonResponse(env, { error: 'Guest name must contain 1 to 160 characters.' }, 400);
        }
        const result = await env.DB.prepare(
            'UPDATE guests SET name = ? WHERE id = ?'
        ).bind(body.name.trim(), guestMatch[1]).run();
        if (!result.meta.changes) {
            return jsonResponse(env, { error: 'Guest not found.' }, 404);
        }
        return jsonResponse(env, { success: true });
    }
    if (guestMatch && request.method === 'DELETE') {
        const result = await env.DB.prepare('DELETE FROM guests WHERE id = ?').bind(guestMatch[1]).run();
        if (!result.meta.changes) {
            return jsonResponse(env, { error: 'Guest not found.' }, 404);
        }
        return jsonResponse(env, { success: true });
    }

    if (path === '/api/admin/wishes' && request.method === 'GET') {
        const { results } = await env.DB.prepare(
            `SELECT guests.name AS guest_name, wishes.message, wishes.updated_at
             FROM wishes
             JOIN guests ON guests.id = wishes.guest_id
             ORDER BY wishes.updated_at DESC`
        ).all();
        return jsonResponse(env, { wishes: results });
    }

    if (path === '/api/admin/photos' && request.method === 'GET') {
        const { results } = await env.DB.prepare(
            `SELECT photo_id, captured_at, style, orientation, telegram_status, telegram_message_id
             FROM photos
             ORDER BY captured_at DESC`
        ).all();
        return jsonResponse(env, { photos: results });
    }

    return jsonResponse(env, { error: 'Not found.' }, 404);
}

async function handlePhotoUpload(request, env) {
    if (!env.BOT_TOKEN || !env.CHAT_ID) {
        return jsonResponse(env, { success: false, error: 'Telegram delivery is not configured.' }, 500);
    }
    if (!env.DB) {
        return jsonResponse(env, { success: false, error: 'The photo database is not configured.' }, 503);
    }

    let formData;
    try {
        formData = await request.formData();
    } catch (error) {
        return jsonResponse(env, { success: false, error: 'Request must use multipart form data.' }, 400);
    }

    const photo = formData.get('photo');
    const photoId = formData.get('photoId');
    const timestamp = formData.get('timestamp');
    const style = formData.get('style');
    const orientation = formData.get('orientation');
    if (!(photo instanceof File) || photo.size === 0 || photo.size > MAX_PHOTO_SIZE) {
        return jsonResponse(env, { success: false, error: 'Photo must be a non-empty image up to 20 MB.' }, 400);
    }
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(photo.type)) {
        return jsonResponse(env, { success: false, error: 'Photo must be a JPEG, PNG, or WebP image.' }, 400);
    }
    if (typeof photoId !== 'string' || !/^[a-zA-Z0-9-]{1,100}$/.test(photoId)
        || typeof timestamp !== 'string' || timestamp.length > 64 || Number.isNaN(Date.parse(timestamp))
        || typeof style !== 'string' || !style.trim() || style.length > 100
        || !['portrait', 'landscape'].includes(orientation)) {
        return jsonResponse(env, { success: false, error: 'Photo metadata is invalid or incomplete.' }, 400);
    }

    const previous = await env.DB.prepare(
        'SELECT telegram_status, telegram_message_id FROM photos WHERE photo_id = ?'
    ).bind(photoId).first();
    if (previous?.telegram_status === 'sent') {
        return jsonResponse(env, {
            success: true,
            photoId,
            messageId: previous.telegram_message_id,
            duplicate: true
        });
    }
    await env.DB.prepare(
        `INSERT INTO photos (photo_id, captured_at, style, orientation, telegram_status)
         VALUES (?, ?, ?, ?, 'pending')
         ON CONFLICT(photo_id) DO UPDATE SET
             captured_at = excluded.captured_at,
             style = excluded.style,
             orientation = excluded.orientation,
             telegram_status = 'pending'`
    ).bind(photoId, timestamp, style.trim(), orientation).run();

    const caption = [
        `Photo ID: ${photoId}`,
        `Timestamp: ${timestamp}`,
        `Style: ${style.trim()}`,
        `Orientation: ${orientation}`
    ].join('\n');
    const telegramForm = new FormData();
    telegramForm.set('chat_id', env.CHAT_ID);
    telegramForm.set('photo', photo, photo.name || `${photoId}.jpg`);
    telegramForm.set('caption', caption);

    let telegramResponse;
    try {
        telegramResponse = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`, {
            method: 'POST',
            body: telegramForm
        });
    } catch (error) {
        await env.DB.prepare("UPDATE photos SET telegram_status = 'failed' WHERE photo_id = ?")
            .bind(photoId).run();
        return jsonResponse(env, { success: false, error: 'Could not reach the Telegram API.' }, 502);
    }

    let telegramResult;
    try {
        telegramResult = await telegramResponse.json();
    } catch (error) {
        await env.DB.prepare("UPDATE photos SET telegram_status = 'failed' WHERE photo_id = ?")
            .bind(photoId).run();
        return jsonResponse(env, { success: false, error: 'Telegram returned an invalid response.' }, 502);
    }
    if (!telegramResponse.ok || !telegramResult || telegramResult.ok !== true) {
        await env.DB.prepare("UPDATE photos SET telegram_status = 'failed' WHERE photo_id = ?")
            .bind(photoId).run();
        return jsonResponse(env, {
            success: false,
            error: telegramResult?.description || 'Telegram could not send the photo.'
        }, 502);
    }

    const messageId = telegramResult.result?.message_id ?? null;
    await env.DB.prepare(
        "UPDATE photos SET telegram_status = 'sent', telegram_message_id = ? WHERE photo_id = ?"
    ).bind(messageId, photoId).run();
    return jsonResponse(env, { success: true, photoId, messageId });
}

export default {
    async fetch(request, env) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders(env) });
        }
        const url = new URL(request.url);
        const path = url.pathname.replace(/\/+$/, '') || '/';

        try {
            if (path === '/' && request.method === 'GET') {
                return jsonResponse(env, { status: 'ok' });
            }
            if (path === '/upload') {
                return request.method === 'POST'
                    ? await handlePhotoUpload(request, env)
                    : jsonResponse(env, { success: false, error: 'Method not allowed.' }, 405);
            }
            if (path === '/api/wishes') {
                return await handlePublicWishes(request, url, env);
            }
            if (path.startsWith('/api/admin/')) {
                return await handleAdminApi(request, url, env);
            }
            return jsonResponse(env, { error: 'Not found.' }, 404);
        } catch (error) {
            console.error('Worker request failed:', error);
            return jsonResponse(env, { error: 'The request could not be completed.' }, 500);
        }
    }
};
