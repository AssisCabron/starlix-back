import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import axios from 'axios';
import path from 'path';

dotenv.config();

const ASAAS_API_URL = process.env.ASAAS_API_URL || 'https://api.asaas.com/v3';
const ASAAS_API_KEY = process.env.ASAAS_API_KEY || '';

console.log('Asaas API URL:', ASAAS_API_URL);
console.log('Asaas API Key Loaded:', ASAAS_API_KEY ? 'YES (Starts with ' + ASAAS_API_KEY.substring(0, 10) + '...)' : 'NO');

const app = express();
const port = process.env.PORT || 4000;

app.use(cors({
    origin: [
        'http://localhost:3000', 
        'https://starlix-back.onrender.com', 
        'https://starlix-7c7d.onrender.com',
        'https://www.starlixmenu.online',
        'https://starlixmenu.online'
    ], // Allow Frontend (Local & Prod)
    credentials: true
}));
app.use(express.json());

// Supabase Admin Client (For bypassing email verification)
console.log("Supabase URL:", process.env.SUPABASE_URL ? "LOADED" : "NOT LOADED");
console.log("Supabase Admin Key:", process.env.SUPABASE_SERVICE_ROLE_KEY ? "LOADED" : "NOT LOADED");
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL || '',
    process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

// Standard Supabase Client (For normal auth/queries)
const supabase = createClient(
    process.env.SUPABASE_URL || '',
    process.env.SUPABASE_ANON_KEY || ''
);

// Signup Proxy (Auto-Confirm)
app.post('/api/auth/signup', async (req: Request, res: Response): Promise<any> => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Use Admin API to create user with email auto-confirmed
        const { data, error } = await supabaseAdmin.auth.admin.createUser({
            email,
            password,
            email_confirm: true // This bypasses email verification
        });

        if (error) {
            console.error("Signup Error:", error);
            return res.status(400).json({ error: error.message });
        }
        
        // Ensure profile exists (Manually create if trigger failed for some reason)
        // This acts as a fallback to your SQL trigger
        if (data.user) {
             const { error: profileError } = await supabaseAdmin
                .from('profiles')
                .insert([
                    { 
                        id: data.user.id, 
                        email: data.user.email,
                        plan: 'Free',
                        status: 'Inactive',
                        hwid: null,
                        license_key: 'NO-LICENSE'
                    }
                ])
                .select()
                .single();
             
             // Ignore error if it's duplicate key (trigger might have worked)
             if (profileError && profileError.code !== '23505') {
                 console.warn("Manual profile creation warning:", profileError);
             }
        }

        return res.json({ message: 'Account created successfully! You can now log in.', user: data.user });
    } catch (err) {
        console.error("Server Error:", err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Login 
app.post('/api/auth/login', async (req: Request, res: Response): Promise<any> => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (error) {
            return res.status(401).json({ error: error.message });
        }

        // Return the session/user to the frontend
        // The frontend can store the access_token in memory or a cookie
        return res.json({ session: data.session, user: data.user });
    } catch (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Profile Logic (Mocked Secure Backend Logic)
// In a real app, this would verify the 'Authorization' header (Bearer token)
// to ensure the request is from a valid user, then fetch the profile from DB.
app.get('/api/user/profile', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({ error: 'Missing Authorization Token' });
    }

    const token = authHeader.replace('Bearer ', '');

    // Verify User with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
         return res.status(401).json({ error: 'Invalid or Expired Token' });
    }

    // --- SECURE DATA FETCH ---
    
    console.log('========================================');
    console.log('[PROFILE ENDPOINT] Fetching profile for user:', user.id);
    console.log('========================================');
    
    // Fetch profile from 'profiles' table using ADMIN client to bypass RLS
    let { data: profile, error: profileError } = await supabaseAdmin
        .from('profiles')
        .select('*')
        .eq('id', user.id)
        .single();

    if (profileError && profileError.code !== 'PGRST116') {
         console.error('Profile fetch error:', profileError);
         return res.status(500).json({ error: 'Failed to fetch profile' });
    }

    console.log('[PROFILE ENDPOINT] Profile exists:', !!profile);
    console.log('[PROFILE ENDPOINT] Profile data:', profile ? {
        id: profile.id,
        email: profile.email,
        is_reseller: profile.is_reseller,
        has_field: 'is_reseller' in profile
    } : 'NULL');

    // If no profile exists (should exist due to trigger, but fallback just in case)
    if (!profile) {
        console.log('[PROFILE ENDPOINT] Creating fallback profile (no DB record found)');
        profile = {
            id: user.id,
            email: user.email,
            plan: "Free",
            status: "Inactive",
            licenseKey: "No License",
            expiresAt: "N/A",
            lastLogin: new Date().toISOString()
        };
    } else {
        // Map DB fields to Frontend expected fields if necessary
        // Assuming DB columns: plan, status, license_key, expires_at
        console.log('[Backend] Raw profile from DB:', {
            id: profile.id,
            email: profile.email,
            is_reseller: profile.is_reseller,
            has_is_reseller_field: 'is_reseller' in profile
        });
        
        profile = {
            ...profile,
            hwid: profile.hwid ? 'Linked' : 'Not Linked',
            licenseKey: profile.license_key || 'No License',
            expiresAt: profile.expires_at ? new Date(profile.expires_at).toLocaleDateString() : 'Never',
            is_reseller: profile.is_reseller || false
        };
    }

    return res.json(profile);
});

// HWID Reset Endpoint
app.post('/api/user/hwid-reset', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    // Fetch current profile to check cooldown
    let { data: profile } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', user.id)
        .single();
    
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const COOLDOWN_DAYS = 7;
    const now = new Date();
    
    if (profile.last_hwid_reset) {
        const lastReset = new Date(profile.last_hwid_reset);
        const diffTime = Math.abs(now.getTime() - lastReset.getTime());
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays < COOLDOWN_DAYS) {
             return res.status(400).json({ error: `Cooldown active. Try again in ${COOLDOWN_DAYS - diffDays} days.` });
        }
    }

    // Perform Reset
    const { error: updateError } = await supabaseAdmin
        .from('profiles')
        .update({ 
            hwid: null,
            last_hwid_reset: now.toISOString()
        })
        .eq('id', user.id);

    if (updateError) return res.status(500).json({ error: 'Failed to reset HWID' });

    return res.json({ message: 'HWID Reset Successfully' });
});

// --- ASAAS INTEGRATION ---

// --- BACKGROUND JOB (POLLING) ---


function generateLicenseKey(amount: number): { key: string, planName: string } {
    const randomPart = Math.random().toString(36).substring(2, 10).toUpperCase() + Math.random().toString(36).substring(2, 10).toUpperCase();
    
    let prefix = 'PREMIUM';
    let planName = 'Premium';

    // Check roughly equal (float comparison)
    if (Math.abs(amount - 9.90) < 0.1) {
        prefix = 'DAILY';
        planName = 'Daily';
    } else if (Math.abs(amount - 29.90) < 0.1) {
        prefix = 'MONTHLY';
        planName = 'Monthly';
    } else if (Math.abs(amount - 149.90) < 0.1) {
        prefix = 'YEARLY';
        planName = 'Yearly';
    } else if (Math.abs(amount - 299.90) < 0.1) {
        prefix = 'LIFETIME';
        planName = 'Lifetime';
    }

    return { 
        key: `${prefix}_${randomPart}`,
        planName
    };
}

async function checkPendingPayments() {
    console.log("Checking pending payments...");
    try {
        // 1. Get all PENDING payments from DB
        console.log(`[${new Date().toLocaleTimeString()}] Poller: Fetching pending payments from DB...`);
        
        // Add a timeout to the database call
        const fetchPromise = supabaseAdmin
            .from('payments')
            .select('*')
            .eq('status', 'PENDING');

        const { data: pendingPayments, error } = await Promise.race([
            fetchPromise,
            new Promise<any>((_, reject) => setTimeout(() => reject(new Error('DB Query Timeout')), 10000))
        ]) as any;

        console.log(`[${new Date().toLocaleTimeString()}] Poller: DB Fetch complete. Error: ${error ? JSON.stringify(error) : 'NONE'}`);

        if (error) {
            console.error(`[${new Date().toLocaleTimeString()}] Poller Error:`, error);
            return;
        }

        if (pendingPayments && pendingPayments.length > 0) {
            console.log(`[${new Date().toLocaleTimeString()}] Poller: Found ${pendingPayments.length} regular payments.`);

            for (const payment of pendingPayments) {
                try {
                    // 2. Check status in Asaas
                    console.log(`Checking Asaas status for ${payment.asaas_id} (Internal ID: ${payment.id})`);
                    const response = await axios.get(`${ASAAS_API_URL}/payments/${payment.asaas_id}`, {
                        headers: { access_token: ASAAS_API_KEY }
                    });

                    const asaasStatus = response.data.status;
                    console.log(`Asaas status for ${payment.asaas_id}: ${asaasStatus}`);

                    if (asaasStatus === 'RECEIVED' || asaasStatus === 'CONFIRMED' || asaasStatus === 'RECEIVED_IN_CASH') {
                        console.log(`Payment confirmed for user ${payment.user_id}`);

                        // 3. Update Payment Status in DB
                        await supabaseAdmin
                            .from('payments')
                            .update({ status: 'PAID' })
                            .eq('id', payment.id);

                        // 4. Generate License Key
                        const { key, planName } = generateLicenseKey(payment.amount);

                        // 5. Update User Profile (Activate Plan & Set Key)
                        // Calculate expiry
                        let expiryDate = new Date();
                        if (planName === 'Daily') expiryDate.setDate(expiryDate.getDate() + 1);
                        else if (planName === 'Monthly') expiryDate.setDate(expiryDate.getDate() + 30);
                        else if (planName === 'Yearly') expiryDate.setDate(expiryDate.getDate() + 365);
                        else if (planName === 'Lifetime') expiryDate.setFullYear(expiryDate.getFullYear() + 99);

                        await supabaseAdmin
                            .from('profiles')
                            .update({
                                plan: planName,
                                status: 'Active',
                                license_key: key,
                                expires_at: expiryDate.toISOString()
                            })
                            .eq('id', payment.user_id);
                    } else if (asaasStatus === 'OVERDUE' || asaasStatus === 'REFUNDED') {
                        // Mark as failed/overdue locally
                        await supabaseAdmin
                            .from('payments')
                            .update({ status: asaasStatus })
                            .eq('id', payment.id);
                    }
                } catch (innerErr: any) {
                    // If payment not found (404), mark as rejected/failed to stop polling
                    if (innerErr.response && innerErr.response.status === 404) {
                        console.log(`Payment ${payment.asaas_id} not found in Asaas. Marking as FAILED.`);
                        await supabaseAdmin
                            .from('payments')
                            .update({ status: 'FAILED' })
                            .eq('id', payment.id);
                    } else {
                        console.error(`Error checking payment ${payment.asaas_id}:`, innerErr.message);
                    }
                }
            }
        } else {
            console.log(`[${new Date().toLocaleTimeString()}] Poller: 0 regular pending payments.`);
        }

        // --- RESELLER CHECK SECTION ---
        console.log(`[${new Date().toLocaleTimeString()}] Poller: Checking reseller purchases...`);

        const { data: resellerPurchases } = await supabaseAdmin
            .from('reseller_purchases')
            .select('*')
            .eq('payment_status', 'pending')
            .eq('keys_generated', false)
            .not('payment_id', 'is', null);

        if (resellerPurchases && resellerPurchases.length > 0) {
            console.log(`[RESELLER POLLER] Found ${resellerPurchases.length} pending purchases to check.`);

            for (const purchase of resellerPurchases) {
                try {
                    const response = await axios.get(`${ASAAS_API_URL}/payments/${purchase.payment_id}`, {
                        headers: { access_token: ASAAS_API_KEY }
                    });

                    const asaasStatus = response.data.status;
                    console.log(`Reseller purchase ${purchase.id} - Asaas status: ${asaasStatus}`);

                    if (asaasStatus === 'RECEIVED' || asaasStatus === 'CONFIRMED' || asaasStatus === 'RECEIVED_IN_CASH') {
                        console.log(`Generating keys for reseller purchase ${purchase.id}`);

                        const keys = [];
                        for (let i = 0; i < purchase.quantity; i++) {
                            const randomPart = Math.random().toString(36).substring(2, 10).toUpperCase() + 
                                             Math.random().toString(36).substring(2, 10).toUpperCase();
                            const licenseKey = `${purchase.plan_type.toUpperCase()}_RESELLER_${randomPart}`;
                            
                            keys.push({
                                reseller_id: purchase.reseller_id,
                                license_key: licenseKey,
                                plan_type: purchase.plan_type,
                                status: 'available'
                            });
                        }

                        await supabaseAdmin.from('reseller_keys').insert(keys);
                        await supabaseAdmin.from('reseller_purchases')
                            .update({ keys_generated: true, payment_status: 'confirmed' })
                            .eq('id', purchase.id);

                        console.log(`Successfully generated ${keys.length} keys for reseller purchase ${purchase.id}`);
                    }
                } catch (err) {
                    console.error(`Error processing reseller purchase ${purchase.id}:`, err);
                }
            }
        }
    } catch (err) {
        console.error("Polling Job Error:", err);
    }
}

// Run polling every 10 seconds (faster updates)
setInterval(() => {
    checkPendingPayments().catch(err => {
        console.error(`[${new Date().toLocaleTimeString()}] CRITICAL: Poller Interval Crash:`, err);
    });
}, 10000);


// --- ASAAS INTEGRATION ---

// 1. Create Payment / Checkout
app.post('/api/payments/checkout', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { planId, billingType, cpfCnpj, name, phone, creditCard } = req.body; 

    if (!cpfCnpj || !name) {
        return res.status(400).json({ error: 'Name and CPF/CNPJ are required.' });
    }

    const type = billingType || 'PIX';

    let price = 0;
    let description = '';

    // HARDCODED PRICES
    switch (planId) {
        case 'daily':
            price = 9.90;
            description = `Starlix Daily - ${user.email}`;
            break;
        case 'monthly':
            price = 29.90;
            description = `Starlix Monthly - ${user.email}`;
            break;
        case 'yearly':
            price = 149.90;
            description = `Starlix Yearly - ${user.email}`;
            break;
        case 'lifetime':
            price = 299.90;
            description = `Starlix Lifetime - ${user.email}`;
            break;
        default:
            return res.status(400).json({ error: 'Invalid Plan Selected' });
    }
    
    try {
        // 2. GET OR CREATE ASAAS CUSTOMER
        // Check if user already has an Asaas Customer ID
        let { data: profile } = await supabaseAdmin
            .from('profiles')
            .select('asaas_customer_id, email')
            .eq('id', user.id)
            .single();

        let customerId = profile?.asaas_customer_id;

        if (!customerId) {
            console.log("Creating new Asaas customer for", user.email);
            // Create Customer in Asaas
            const customerResponse = await axios.post(`${ASAAS_API_URL}/customers`, {
                name: name || user.email, 
                email: user.email,
                cpfCnpj: cpfCnpj,
                phone: phone,
                mobilePhone: phone
            }, {
                headers: { access_token: ASAAS_API_KEY }
            });

            customerId = customerResponse.data.id;

            // Save to Profile
            await supabaseAdmin
                .from('profiles')
                .update({ asaas_customer_id: customerId })
                .eq('id', user.id);
        } else {
            // Update existing customer info (Asaas often requires full info for Credit Card)
            try {
                await axios.post(`${ASAAS_API_URL}/customers/${customerId}`, {
                   name: name,
                   cpfCnpj: cpfCnpj,
                   phone: phone,
                   mobilePhone: phone
                }, {
                   headers: { access_token: ASAAS_API_KEY }
                });
            } catch (updateErr) {
                console.warn("Failed to update Asaas customer info:", updateErr);
            }
        }

        // 3. CREATE PAYMENT
        const paymentPayload: any = {
            customer: customerId, 
            billingType: type, // 'PIX' or 'CREDIT_CARD'
            value: price,
            dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().split('T')[0], // Tomorrow
            description: description,
            externalReference: user.id
        };

        if (type === 'CREDIT_CARD' && creditCard) {
            paymentPayload.creditCard = creditCard;
            paymentPayload.creditCardHolderInfo = {
                name: name,
                email: user.email,
                cpfCnpj: cpfCnpj,
                postalCode: '00000000', // Mocking for now as we didn't ask, but Asaas needs it. In prod, ask user.
                addressNumber: '0',
                phone: phone
            };
        }

        const response = await axios.post(`${ASAAS_API_URL}/payments`, {
            ...paymentPayload
        }, {
            headers: { access_token: ASAAS_API_KEY }
        });

        // SAVE PAYMENT TO DB
        const returnedStatus = response.data.status; 
        console.log(`DB: Attempting to save payment ${response.data.id} for user ${user.id} with status ${returnedStatus}`);
        
        const { error: insertError } = await supabaseAdmin.from('payments').insert({
            user_id: user.id,
            asaas_id: response.data.id,
            amount: price,
            status: returnedStatus, // Could be PENDING or CONFIRMED
            invoice_url: response.data.invoiceUrl
        });

        if (insertError) {
            console.error("DB: Payment Insert Error:", insertError);
        } else {
            console.log(`DB: Payment ${response.data.id} saved successfully.`);
        }

        // 4. IMMEDIATE ACTIVATION CHECK (For Credit Card)
        if (returnedStatus === 'CONFIRMED' || returnedStatus === 'RECEIVED') {
             try {
                 console.log(`Immediate confirmation for payment ${response.data.id}. Status: ${returnedStatus}`);
                 const { key, planName } = generateLicenseKey(price);

                 // Calculate expiry based on plan
                 let expiryDate = new Date();
                 if (planName === 'Daily') expiryDate.setDate(expiryDate.getDate() + 1);
                 else if (planName === 'Monthly') expiryDate.setDate(expiryDate.getDate() + 30);
                 else if (planName === 'Yearly') expiryDate.setDate(expiryDate.getDate() + 365);
                 else if (planName === 'Lifetime') expiryDate.setFullYear(expiryDate.getFullYear() + 99);

                 const { error: profileUpdateError } = await supabaseAdmin
                    .from('profiles')
                    .update({
                        plan: planName,
                        status: 'Active',
                        license_key: key,
                        expires_at: expiryDate.toISOString()
                    })
                    .eq('id', user.id);

                 if (profileUpdateError) {
                     console.error("Immediate Profile Update Error:", profileUpdateError);
                 } else {
                     console.log(`Profile updated successfully for user ${user.id} with plan ${planName}`);
                 }
             } catch (actErr) {
                 console.error("Immediate Activation Catch Error:", actErr);
             }
        }

        let pixData = null;
        if (returnedStatus === 'PENDING' && type === 'PIX') {
            try {
                const pixResponse = await axios.get(`${ASAAS_API_URL}/payments/${response.data.id}/pixQrCode`, {
                    headers: { access_token: ASAAS_API_KEY }
                });
                pixData = {
                    encodedImage: pixResponse.data.encodedImage,
                    payload: pixResponse.data.payload,
                    expirationDate: pixResponse.data.expirationDate
                };
            } catch (pixErr) {
                console.warn("Failed to fetch PIX QR Code:", pixErr);
            }
        }

        console.log(`Checkout response sent for payment ${response.data.id}. Internal PIX data: ${pixData ? 'YES' : 'NO'}`);
        return res.json({ 
            paymentId: response.data.id, 
            invoiceUrl: response.data.invoiceUrl,
            pixQrCode: response.data.bankSlipUrl, // Legacy/Backup
            pix: pixData, // Internal PIX Data
            status: returnedStatus
        });

    } catch (err: any) {
        const errorMsg = err.response?.data?.errors?.[0]?.description || err.message;
        console.error("Asaas Payment Error:", err.response?.data || errorMsg);
        return res.status(500).json({ error: 'Payment failed: ' + errorMsg });
    }
});

// 2. Webhook Handler (Deprecated in favor of polling, but kept for redundancy if needed)
app.post('/api/webhooks/asaas', async (req: Request, res: Response): Promise<any> => {
    // ... logic remains or can be ignored ...
    return res.json({ received: true });
});

// 3. Billing History
app.get('/api/user/billing', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { data: paymentHistory } = await supabase
        .from('payments')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false });

    return res.json({ history: paymentHistory || [] });
});

// 4. Payment Status Polling
app.get('/api/payments/status/:asaas_id', async (req: Request, res: Response): Promise<any> => {
    const { asaas_id } = req.params;

    try {
        // 1. Check in regular payments
        const { data: payment } = await supabaseAdmin
            .from('payments')
            .select('status')
            .eq('asaas_id', asaas_id)
            .single();

        if (payment) {
            return res.json({ status: payment.status });
        }

        // 2. Check in reseller purchases
        const { data: purchase } = await supabaseAdmin
            .from('reseller_purchases')
            .select('payment_status')
            .eq('payment_id', asaas_id)
            .single();

        if (purchase) {
            // Map 'confirmed' to 'CONFIRMED' for frontend consistency if needed
            const status = purchase.payment_status?.toUpperCase() || 'PENDING';
            return res.json({ status });
        }

        return res.status(404).json({ error: 'Payment not found' });
    } catch (err) {
        console.error('Status check error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});


// --- RESELLER SYSTEM ---

// Wholesale pricing for resellers
const WHOLESALE_PRICES: Record<string, number> = {
    daily: 7.00,
    monthly: 20.00,
    yearly: 100.00,
    lifetime: 200.00
};

// 1. Get Reseller Dashboard Stats
app.get('/api/reseller/dashboard', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    // Check if user is a reseller
    const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('is_reseller, reseller_balance, reseller_total_sales')
        .eq('id', user.id)
        .single();

    if (!profile?.is_reseller) {
        return res.status(403).json({ error: 'Not authorized as reseller' });
    }

    // Get available keys count by plan type
    const { data: availableKeys } = await supabaseAdmin
        .from('reseller_keys')
        .select('plan_type')
        .eq('reseller_id', user.id)
        .eq('status', 'available');

    const keysByPlan = {
        Daily: 0,
        Monthly: 0,
        Yearly: 0,
        Lifetime: 0
    };

    availableKeys?.forEach((key: any) => {
        keysByPlan[key.plan_type as keyof typeof keysByPlan]++;
    });

    return res.json({
        balance: profile.reseller_balance,
        totalSales: profile.reseller_total_sales,
        availableKeys: keysByPlan
    });
});

// 2. Get Wholesale Prices
app.get('/api/reseller/wholesale-prices', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('is_reseller')
        .eq('id', user.id)
        .single();

    if (!profile?.is_reseller) {
        return res.status(403).json({ error: 'Not authorized as reseller' });
    }

    return res.json(WHOLESALE_PRICES);
});

// 3. Purchase Wholesale Keys
app.post('/api/reseller/purchase-keys', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });


    const { planType, quantity, billingType, cpfCnpj, name, phone, creditCard } = req.body;

    if (!planType || !quantity || quantity < 1) {
        return res.status(400).json({ error: 'Invalid plan type or quantity' });
    }

    if (!billingType || !cpfCnpj || !name || !phone) {
        return res.status(400).json({ error: 'Missing required payment information' });
    }

    const planKey = planType.toLowerCase();
    const unitCost = WHOLESALE_PRICES[planKey];

    if (!unitCost) {
        return res.status(400).json({ error: 'Invalid plan type' });
    }

    const totalCost = unitCost * quantity;

    try {
        // Get or create Asaas customer for reseller
        const { data: profile } = await supabaseAdmin
            .from('profiles')
            .select('asaas_customer_id, email')
            .eq('id', user.id)
            .single();

        let customerId = profile?.asaas_customer_id;

        // Verify if customer exists in Asaas (in case of env switch or deleted customer)
        if (customerId) {
            try {
                await axios.get(`${ASAAS_API_URL}/customers/${customerId}`, {
                    headers: { access_token: ASAAS_API_KEY }
                });
                console.log('Using existing valid Asaas customer:', customerId);
            } catch (err: any) {
                if (err.response?.status === 404) {
                    console.log('Stale customer ID found, marking for re-creation:', customerId);
                    customerId = null;
                } else {
                    console.error('Error verifying customer:', err.message);
                }
            }
        }

        if (!customerId) {
            console.log('Creating new Asaas customer for reseller:', profile?.email);
            const customerResponse = await axios.post(`${ASAAS_API_URL}/customers`, {
                name,
                cpfCnpj,
                email: profile?.email,
                phone
            }, {
                headers: { access_token: ASAAS_API_KEY }
            });

            customerId = customerResponse.data.id;
            console.log('New Asaas customer created:', customerId);

            await supabaseAdmin
                .from('profiles')
                .update({ asaas_customer_id: customerId })
                .eq('id', user.id);
        }

        // Create Asaas payment
        const paymentPayload: any = {
            customer: customerId,
            billingType,
            value: totalCost,
            dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().split('T')[0],
            description: `Wholesale purchase: ${quantity}x ${planType} keys`
        };

        if (billingType === 'CREDIT_CARD' && creditCard) {
            paymentPayload.creditCard = {
                holderName: creditCard.holderName,
                number: creditCard.number,
                expiryMonth: creditCard.expiryMonth,
                expiryYear: creditCard.expiryYear,
                ccv: creditCard.ccv
            };
            paymentPayload.creditCardHolderInfo = {
                name,
                cpfCnpj,
                phone
            };
        }

        const paymentResponse = await axios.post(`${ASAAS_API_URL}/payments`, paymentPayload, {
            headers: { access_token: ASAAS_API_KEY }
        });

        const paymentId = paymentResponse.data.id;
        const paymentStatus = paymentResponse.data.status;

        // Record purchase in database
        const { data: purchase, error: insertError } = await supabaseAdmin.from('reseller_purchases').insert({
            reseller_id: user.id,
            plan_type: planType,
            quantity,
            unit_cost: unitCost,
            total_cost: totalCost,
            payment_id: paymentId,
            payment_status: paymentStatus === 'CONFIRMED' || paymentStatus === 'RECEIVED' ? 'confirmed' : 'pending',
            keys_generated: false
        }).select().single();

        if (insertError) {
            console.error("DB: Reseller Purchase Insert Error:", insertError);
            // Even if DB insert fails, we return the payment data if we have it, 
            // but log the error for debugging.
        }

        // If payment is immediately confirmed (credit card), generate keys
        if (paymentStatus === 'CONFIRMED' || paymentStatus === 'RECEIVED') {
            const keys = [];
            for (let i = 0; i < quantity; i++) {
                const randomPart = Math.random().toString(36).substring(2, 10).toUpperCase() + 
                                 Math.random().toString(36).substring(2, 10).toUpperCase();
                const licenseKey = `${planType.toUpperCase()}_RESELLER_${randomPart}`;
                
                keys.push({
                    reseller_id: user.id,
                    license_key: licenseKey,
                    plan_type: planType,
                    status: 'available'
                });
            }

            await supabaseAdmin.from('reseller_keys').insert(keys);
            await supabaseAdmin.from('reseller_purchases')
                .update({ keys_generated: true, payment_status: 'confirmed' })
                .eq('id', purchase.id);

            return res.json({
                success: true,
                paymentId,
                status: 'CONFIRMED',
                keys: keys.map(k => k.license_key),
                message: `Successfully purchased ${quantity} ${planType} keys`
            });
        }

        // For PIX, fetch QR code
        let pixData = null;
        if (billingType === 'PIX') {
            try {
                const pixResponse = await axios.get(`${ASAAS_API_URL}/payments/${paymentId}/pixQrCode`, {
                    headers: { access_token: ASAAS_API_KEY }
                });
                pixData = {
                    encodedImage: pixResponse.data.encodedImage,
                    payload: pixResponse.data.payload,
                    expirationDate: pixResponse.data.expirationDate
                };
            } catch (pixErr) {
                console.warn('Failed to fetch PIX QR Code:', pixErr);
            }
        }

        return res.json({
            success: true,
            paymentId,
            status: paymentStatus,
            pix: pixData,
            invoiceUrl: paymentResponse.data.invoiceUrl,
            message: 'Payment created. Keys will be generated upon confirmation.'
        });
    } catch (err: any) {
        console.error('Reseller purchase error:', err.response?.data || err.message);
        if (err.response?.data?.errors) {
            console.error('Asaas Errors:', JSON.stringify(err.response.data.errors, null, 2));
        }
        return res.status(500).json({ 
            error: 'Failed to process purchase', 
            details: err.response?.data?.errors || err.message 
        });
    }
});

// 4. List Reseller Keys
app.get('/api/reseller/keys', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { data: keys } = await supabaseAdmin
        .from('reseller_keys')
        .select('*')
        .eq('reseller_id', user.id)
        .order('created_at', { ascending: false });

    return res.json({ keys: keys || [] });
});

// 5. Request Withdrawal
app.post('/api/reseller/withdraw', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { amount, pixKey } = req.body;

    if (!amount || amount <= 0 || !pixKey) {
        return res.status(400).json({ error: 'Invalid amount or PIX key' });
    }

    // Check balance
    const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('is_reseller, reseller_balance')
        .eq('id', user.id)
        .single();

    if (!profile?.is_reseller) {
        return res.status(403).json({ error: 'Not authorized as reseller' });
    }

    if (profile.reseller_balance < amount) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }

    try {
        // Create withdrawal request
        await supabaseAdmin.from('withdrawal_requests').insert({
            reseller_id: user.id,
            amount,
            pix_key: pixKey,
            status: 'pending'
        });

        return res.json({ message: 'Withdrawal request submitted successfully' });
    } catch (err) {
        console.error('Withdrawal request error:', err);
        return res.status(500).json({ error: 'Failed to submit withdrawal request' });
    }
});

// 6. Get Withdrawal History
app.get('/api/reseller/withdrawals', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { data: withdrawals } = await supabaseAdmin
        .from('withdrawal_requests')
        .select('*')
        .eq('reseller_id', user.id)
        .order('created_at', { ascending: false });

    return res.json({ withdrawals: withdrawals || [] });
});

// Download Route (Mocked security)
app.get('/api/download/loader', (req: Request, res: Response) => {
    // In real app, verify token again before redirecting for download
    res.json({ url: "https://starlix.net/download/loader_v2.exe" });
});

// Health Check
app.get('/health', (req: Request, res: Response) => {
    res.status(200).send('OK');
});

// 7. Redeem License Key (Reseller Key)
app.post('/api/payments/redeem-key', async (req: Request, res: Response): Promise<any> => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Missing Token' });
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid Token' });

    const { licenseKey } = req.body;

    if (!licenseKey) {
        return res.status(400).json({ error: 'License key is required' });
    }

    try {
        // 1. Check if key exists and is available
        const { data: keyData, error: keyError } = await supabaseAdmin
            .from('reseller_keys')
            .select('*')
            .eq('license_key', licenseKey)
            .eq('status', 'available')
            .single();

        if (keyError || !keyData) {
            return res.status(404).json({ error: 'Invalid or already used license key' });
        }

        // 2. Calculate expiry based on plan type
        let expiryDate = new Date();
        const planName = keyData.plan_type;
        if (planName === 'Daily') expiryDate.setDate(expiryDate.getDate() + 1);
        else if (planName === 'Monthly') expiryDate.setDate(expiryDate.getDate() + 30);
        else if (planName === 'Yearly') expiryDate.setDate(expiryDate.getDate() + 365);
        else if (planName === 'Lifetime') expiryDate.setFullYear(expiryDate.getFullYear() + 99);

        // 3. Update User Profile
        const { error: profileUpdateError } = await supabaseAdmin
            .from('profiles')
            .update({
                plan: planName,
                status: 'Active',
                license_key: licenseKey,
                expires_at: expiryDate.toISOString()
            })
            .eq('id', user.id);

        if (profileUpdateError) throw profileUpdateError;

        // 4. Update Key Status
        await supabaseAdmin
            .from('reseller_keys')
            .update({
                status: 'activated',
                sold_to_user_id: user.id,
                activated_at: new Date().toISOString()
            } as any)
            .eq('id', keyData.id);

        // 5. Update Reseller Sales Info
        await supabaseAdmin
            .from('profiles')
            .update({ 
                reseller_total_sales: (await supabaseAdmin.from('profiles').select('reseller_total_sales').eq('id', keyData.reseller_id).single()).data?.reseller_total_sales + 1 
            } as any)
            .eq('id', keyData.reseller_id);

        return res.json({
            success: true,
            message: `Key redeemed successfully! Plan ${planName} activated.`,
            plan: planName,
            expiresAt: expiryDate.toLocaleDateString()
        });

    } catch (err: any) {
        console.error('Key redemption error:', err);
        return res.status(500).json({ error: 'Failed to redeem key' });
    }
});

// Download AnyDesk Route
app.get('/api/download/anydesk', (req: Request, res: Response) => {
    // Try process.cwd() first, then fallback to __dirname
    let filePath = path.join(process.cwd(), 'd', 'AnyDesk.zip');
    
    // In prod (dist), process.cwd() should still be the backend root
    // but let's be double sure and check if it exists or adjust
    res.download(filePath, 'AnyDesk.zip', (err) => {
        if (err) {
            console.error('Download error with process.cwd():', err);
            // Fallback to __dirname (works in dev)
            const fallbackPath = path.join(__dirname, 'd', 'AnyDesk.zip');
            res.download(fallbackPath, 'AnyDesk.zip', (err2) => {
                if (err2) {
                    console.error('Download error with fallback:', err2);
                    if (!res.headersSent) {
                        res.status(500).json({ error: 'Could not download the file.' });
                    }
                }
            });
        }
    });
});

// Download Starlix Loader Route
app.get('/api/download/loader', (req: Request, res: Response) => {
    let filePath = path.join(process.cwd(), 'd', 'starlix.zip');
    res.download(filePath, 'starlix.zip', (err) => {
        if (err) {
            console.error('Download error with process.cwd():', err);
            const fallbackPath = path.join(__dirname, 'd', 'starlix.zip');
            res.download(fallbackPath, 'starlix.zip', (err2) => {
                if (err2) {
                    console.error('Download error with fallback:', err2);
                    if (!res.headersSent) {
                        res.status(500).json({ error: 'Could not download the file.' });
                    }
                }
            });
        }
    });
});

// Start Server       
app.listen(port, () => {
    console.log(`Backend Server running on port ${port}`);
});
