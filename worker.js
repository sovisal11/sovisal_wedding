const MAX_PHOTO_SIZE = 20 * 1024 * 1024;
const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
};

function jsonResponse(body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            ...CORS_HEADERS,
            'Content-Type': 'application/json; charset=utf-8'
        }
    });
}

function getTextField(formData, name, maxLength) {
    const value = formData.get(name);
    if (typeof value !== 'string') {
        return null;
    }
    const trimmedValue = value.trim();
    return trimmedValue && trimmedValue.length <= maxLength ? trimmedValue : null;
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname.replace(/\/+$/, '') || '/';

        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: CORS_HEADERS });
        }

        if (path === '/' && request.method === 'GET') {
            return jsonResponse({ status: 'ok' });
        }

        if (path !== '/upload') {
            return jsonResponse({ success: false, error: 'Not found.' }, 404);
        }
        if (request.method !== 'POST') {
            return jsonResponse({ success: false, error: 'Method not allowed.' }, 405);
        }
        if (!env.BOT_TOKEN || !env.CHAT_ID) {
            return jsonResponse({ success: false, error: 'Telegram delivery is not configured.' }, 500);
        }

        let formData;
        try {
            formData = await request.formData();
        } catch (error) {
            return jsonResponse({ success: false, error: 'Request must use multipart form data.' }, 400);
        }

        const photo = formData.get('photo');
        const photoId = getTextField(formData, 'photoId', 100);
        const timestamp = getTextField(formData, 'timestamp', 64);
        const style = getTextField(formData, 'style', 100);
        const orientation = getTextField(formData, 'orientation', 32);

        if (!(photo instanceof File) || photo.size === 0 || photo.size > MAX_PHOTO_SIZE) {
            return jsonResponse({ success: false, error: 'Photo must be a non-empty image up to 20 MB.' }, 400);
        }
        if (!['image/jpeg', 'image/png', 'image/webp'].includes(photo.type)) {
            return jsonResponse({ success: false, error: 'Photo must be a JPEG, PNG, or WebP image.' }, 400);
        }
        if (!photoId || !timestamp || Number.isNaN(Date.parse(timestamp)) || !style || !orientation) {
            return jsonResponse({
                success: false,
                error: 'photoId, a valid timestamp, style, and orientation are required.'
            }, 400);
        }

        const caption = [
            `Photo ID: ${photoId}`,
            `Timestamp: ${timestamp}`,
            `Style: ${style}`,
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
            return jsonResponse({ success: false, error: 'Could not reach the Telegram API.' }, 502);
        }

        let telegramResult;
        try {
            telegramResult = await telegramResponse.json();
        } catch (error) {
            return jsonResponse({ success: false, error: 'Telegram returned an invalid response.' }, 502);
        }
        if (!telegramResponse.ok || !telegramResult || telegramResult.ok !== true) {
            return jsonResponse({
                success: false,
                error: telegramResult?.description || 'Telegram could not send the photo.'
            }, 502);
        }

        return jsonResponse({
            success: true,
            photoId,
            messageId: telegramResult?.result?.message_id ?? null
        });
    }
};
