const PACKS = {
    "50": {
        crystals: 50,
        stars: 10
    },

    "200": {
        crystals: 200,
        stars: 35
    }
};


// ============================================================
// CORS
// ============================================================

function corsHeaders(origin) {

    return {
        "Access-Control-Allow-Origin": origin || "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Content-Type": "application/json"
    };

}


function json(data, status = 200, origin = "*") {

    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: corsHeaders(origin)
        }
    );

}


// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initDatabase(env) {

    await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY,
            crystals INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    `).run();


    await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            telegram_id TEXT NOT NULL,
            crystals INTEGER NOT NULL,
            stars INTEGER NOT NULL,
            status TEXT NOT NULL,
            charge_id TEXT,
            created_at TEXT NOT NULL,
            paid_at TEXT
        )
    `).run();

}


// ============================================================
// HMAC SHA-256
// ============================================================

async function hmacSha256(keyBytes, dataBytes) {

    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        {
            name: "HMAC",
            hash: "SHA-256"
        },
        false,
        ["sign"]
    );

    return new Uint8Array(
        await crypto.subtle.sign(
            "HMAC",
            key,
            dataBytes
        )
    );

}


function bytesToHex(bytes) {

    return [...bytes]
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");

}


// ============================================================
// TELEGRAM MINI APP AUTHENTICATION
// ============================================================

async function validateTelegramInitData(
    initData,
    botToken
) {

    if (!initData) {
        throw new Error(
            "Telegram initData отсутствует"
        );
    }


    if (!botToken) {
        throw new Error(
            "BOT_TOKEN не настроен"
        );
    }


    const params =
        new URLSearchParams(initData);


    const receivedHash =
        params.get("hash");


    if (!receivedHash) {
        throw new Error(
            "Telegram hash отсутствует"
        );
    }


    const authDate =
        Number(
            params.get("auth_date") || 0
        );


    if (!authDate) {
        throw new Error(
            "Некорректный auth_date"
        );
    }


    const currentTime =
        Math.floor(
            Date.now() / 1000
        );


    // Сессия не должна быть старше суток
    if (
        currentTime - authDate >
        86400
    ) {

        throw new Error(
            "Telegram-сессия устарела"
        );

    }


    const dataPairs = [];


    for (
        const [key, value]
        of params.entries()
    ) {

        if (key === "hash") {
            continue;
        }


        dataPairs.push(
            `${key}=${value}`
        );

    }


    dataPairs.sort();


    const dataCheckString =
        dataPairs.join("\n");


    const secretKey =
        await hmacSha256(
            new TextEncoder().encode(
                "WebAppData"
            ),
            new TextEncoder().encode(
                botToken
            )
        );


    const calculatedHash =
    bytesToHex(
            await hmacSha256(
                secretKey,
                new TextEncoder().encode(
                    dataCheckString
                )
            )
        );


    if (
        calculatedHash !==
        receivedHash
    ) {

        throw new Error(
            "Проверка Telegram подписи не пройдена"
        );

    }


    const userString =
        params.get("user");


    if (!userString) {

        throw new Error(
            "Telegram user отсутствует"
        );

    }


    const user =
        JSON.parse(userString);


    if (!user || !user.id) {

        throw new Error(
            "Некорректный Telegram user"
        );

    }


    return user;

}


// ============================================================
// TELEGRAM BOT API
// ============================================================

async function telegramApi(
    env,
    method,
    body
) {

    const response =
        await fetch(
            `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(body)
            }
        );


    const data =
        await response.json();


    if (!data.ok) {

        throw new Error(
            data.description ||
            `Telegram API error: ${method}`
        );

    }


    return data.result;

}


// ============================================================
// USER
// ============================================================

async function ensureUser(
    env,
    telegramId
) {

    const existing =
        await env.DB
            .prepare(
                `
                SELECT telegram_id
                FROM users
                WHERE telegram_id = ?
                `
            )
            .bind(
                String(telegramId)
            )
            .first();


    if (!existing) {

        await env.DB
            .prepare(
                `
                INSERT INTO users
                (
                    telegram_id,
                    crystals,
                    created_at
                )
                VALUES (?, ?, ?)
                `
            )
            .bind(
                String(telegramId),
                10,
                new Date().toISOString()
            )
            .run();

    }

}


// ============================================================
// CREATE INVOICE
// ============================================================

async function createInvoice(
    request,
    env,
    origin
) {

    const body =
        await request.json();


    const user =
        await validateTelegramInitData(
            body.initData,
            env.BOT_TOKEN
        );


    const pack =
        body.pack || {};


    const crystals =
        Number(pack.crystals);


    const stars =
        Number(pack.stars);


    const allowedPack =
        PACKS[String(crystals)];


    if (!allowedPack) {

        return json(
            {
                error:
                    "Такого набора кристаллов нет"
            },
            400,
            origin
        );

    }


    if (
        allowedPack.stars !==
        stars
    ) {

        return json(
            {
                error:
                    "Неверная цена набора"
            },
            400,
            origin
        );

    }


    await ensureUser(
        env,
        user.id
    );


    const orderId =
        crypto.randomUUID();


    const payload =
        `airclicker:${orderId}`;


    await env.DB
        .prepare(
            `
            INSERT INTO orders
            (
                id,
                telegram_id,
                crystals,
                stars,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            `
          )
        .bind(
            orderId,
            String(user.id),
            crystals,
            stars,
            "pending",
            new Date().toISOString()
        )
        .run();


    const invoiceUrl =
        await telegramApi(
            env,
            "createInvoiceLink",
            {
                title:
                    `${crystals} 💎 AirClicker`,

                description:
                    `Пополнение AirClicker на ${crystals} кристаллов.`,

                payload,

                currency:
                    "XTR",

                prices: [
                    {
                        label:
                            `${crystals} кристаллов`,
                        amount:
                            stars
                    }
                ]
            }
        );


    return json(
        {
            success: true,
            invoiceUrl
        },
        200,
        origin
    );

}


// ============================================================
// GET BALANCE
// ============================================================

async function getBalance(
    request,
    env,
    origin
) {

    const body =
        await request.json();


    const user =
        await validateTelegramInitData(
            body.initData,
            env.BOT_TOKEN
        );


    await ensureUser(
        env,
        user.id
    );


    const row =
        await env.DB
            .prepare(
                `
                SELECT crystals
                FROM users
                WHERE telegram_id = ?
                `
            )
            .bind(
                String(user.id)
            )
            .first();


    return json(
        {
            success: true,
            crystals:
                Number(
                    row?.crystals || 0
                )
        },
        200,
        origin
    );

}


// ============================================================
// TELEGRAM WEBHOOK
// ============================================================

async function telegramWebhook(
    request,
    env
) {

    const update =
        await request.json();


    // --------------------------------------------------------
    // PRE-CHECKOUT
    // --------------------------------------------------------

    if (
        update.pre_checkout_query
    ) {

        const query =
            update.pre_checkout_query;


        const payload =
            query.invoice_payload ||
            "";


        if (
            !payload.startsWith(
                "airclicker:"
            )
        ) {

            await telegramApi(
                env,
                "answerPreCheckoutQuery",
                {
                    pre_checkout_query_id:
                        query.id,

                    ok: false,

                    error_message:
                        "Неверный счёт."
                }
            );


            return new Response("OK");

        }


        const orderId =
            payload.replace(
                "airclicker:",
                ""
            );


        const order =
            await env.DB
                .prepare(
                    `
                    SELECT
                        id,
                        telegram_id,
                        crystals,
                        stars,
                        status
                    FROM orders
                    WHERE id = ?
                    `
                )
                .bind(orderId)
                .first();


        if (!order) {

            await telegramApi(
                env,
                "answerPreCheckoutQuery",
                {
                    pre_checkout_query_id:
                        query.id,

                    ok: false,

                    error_message:
                        "Заказ не найден."
                }
            );


            return new Response("OK");

        }


        if (
          order.status !==
            "pending"
        ) {

            await telegramApi(
                env,
                "answerPreCheckoutQuery",
                {
                    pre_checkout_query_id:
                        query.id,

                    ok: false,

                    error_message:
                        "Этот заказ уже обработан."
                }
            );


            return new Response("OK");

        }


        if (
            Number(order.stars) !==
            Number(query.total_amount)
        ) {

            await telegramApi(
                env,
                "answerPreCheckoutQuery",
                {
                    pre_checkout_query_id:
                        query.id,

                    ok: false,

                    error_message:
                        "Неверная сумма платежа."
                }
            );


            return new Response("OK");

        }


        await telegramApi(
            env,
            "answerPreCheckoutQuery",
            {
                pre_checkout_query_id:
                    query.id,

                ok: true
            }
        );


        return new Response("OK");

    }


    // --------------------------------------------------------
    // SUCCESSFUL PAYMENT
    // --------------------------------------------------------

    const payment =
        update
            .message
            ?.successful_payment;


    if (payment) {

        const payload =
            payment.invoice_payload ||
            "";


        if (
            !payload.startsWith(
                "airclicker:"
            )
        ) {

            return new Response("OK");

        }


        const orderId =
            payload.replace(
                "airclicker:",
                ""
            );


        const order =
            await env.DB
                .prepare(
                    `
                    SELECT
                        id,
                        telegram_id,
                        crystals,
                        stars,
                        status
                    FROM orders
                    WHERE id = ?
                    `
                )
                .bind(orderId)
                .first();


        if (!order) {

            return new Response(
                "Order not found",
                {
                    status: 404
                }
            );

        }


        // Уже обработанный заказ
        if (
            order.status ===
            "paid"
        ) {

            return new Response("OK");

        }


        if (
            Number(order.stars) !==
            Number(payment.total_amount)
        ) {

            return new Response(
                "Payment amount mismatch",
                {
                    status: 400
                }
            );

        }


        // ----------------------------------------------------
        // НАЧИСЛЕНИЕ КРИСТАЛЛОВ
        // ----------------------------------------------------

        await ensureUser(
            env,
            order.telegram_id
        );


        await env.DB
            .prepare(
                `
                UPDATE users
                SET crystals =
                    crystals + ?
                WHERE telegram_id = ?
                `
            )
            .bind(
                Number(order.crystals),
                String(order.telegram_id)
            )
            .run();


        // ----------------------------------------------------
        // ПОМЕЧАЕМ ЗАКАЗ ОПЛАЧЕННЫМ
        // ----------------------------------------------------

        await env.DB
            .prepare(
                `
                UPDATE orders
                SET
                    status = ?,
                    charge_id = ?,
                    paid_at = ?
                WHERE id = ?
                AND status = ?
                `
            )
            .bind(
              "paid",

                payment
                    .telegram_payment_charge_id,

                new Date().toISOString(),

                orderId,

                "pending"
            )
            .run();


        return new Response("OK");

    }


    return new Response("OK");

}


// ============================================================
// MAIN WORKER
// ============================================================

export default {

    async fetch(
        request,
        env
    ) {

        const origin =
            request.headers.get(
                "Origin"
            ) || "*";


        // CORS preflight

        if (
            request.method ===
            "OPTIONS"
        ) {

            return new Response(
                null,
                {
                    status: 204,
                    headers:
                        corsHeaders(origin)
                }
            );

        }


        try {

            await initDatabase(
                env
            );


            const url =
                new URL(
                    request.url
                );


            // ------------------------------------------------
            // CREATE INVOICE
            // ------------------------------------------------

            if (
                url.pathname ===
                "/create-invoice"
                &&
                request.method ===
                "POST"
            ) {

                return await createInvoice(
                    request,
                    env,
                    origin
                );

            }


            // ------------------------------------------------
            // BALANCE
            // ------------------------------------------------

            if (
                url.pathname ===
                "/balance"
                &&
                request.method ===
                "POST"
            ) {

                return await getBalance(
                    request,
                    env,
                    origin
                );

            }


            // ------------------------------------------------
            // TELEGRAM WEBHOOK
            // ------------------------------------------------

            if (
                url.pathname ===
                "/telegram/webhook"
                &&
                request.method ===
                "POST"
            ) {

                return await telegramWebhook(
                    request,
                    env
                );

            }


            return json(
                {
                    ok: true,
                    service:
                        "AirClicker Telegram Stars"
                },
                200,
                origin
            );

        }
        catch (error) {

            return json(
                {
                    ok: false,
                    error:
                        error.message ||
                        "Server error"
                },
                500,
                origin
            );

        }

    }

};
