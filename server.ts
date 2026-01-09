import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import axios from 'axios';

dotenv.config();

const ASAAS_API_URL = process.env.ASAAS_API_URL || 'https://sandbox.asaas.com/api/v3';
const ASAAS_API_KEY = process.env.ASAAS_API_KEY || '';

const app = express();
const port = process.env.PORT || 4000;

app.use(cors({
    origin: ['http://localhost:3000', 'https://starlix-back.onrender.com'], // Allow Frontend (Local & Prod)
    credentials: true
}));
app.use(express.json());

// Supabase Admin Client (For bypassing email verification)
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
    
    // Fetch profile from 'profiles' table
    let { data: profile, error: profileError } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', user.id)
        .single();

    if (profileError && profileError.code !== 'PGRST116') {
         console.error('Profile fetch error:', profileError);
         return res.status(500).json({ error: 'Failed to fetch profile' });
    }

    // If no profile exists (should exist due to trigger, but fallback just in case)
    if (!profile) {
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
        profile = {
            ...profile,
            hwid: profile.hwid ? 'Linked' : 'Not Linked',
            licenseKey: profile.license_key || 'No License',
            expiresAt: profile.expires_at ? new Date(profile.expires_at).toLocaleDateString() : 'Never'
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
        const { data: pendingPayments, error } = await supabaseAdmin
            .from('payments')
            .select('*')
            .eq('status', 'PENDING');

        if (error || !pendingPayments || pendingPayments.length === 0) return;

        for (const payment of pendingPayments) {
            try {
                // 2. Check status in Asaas
                const response = await axios.get(`${ASAAS_API_URL}/payments/${payment.asaas_id}`, {
                    headers: { access_token: ASAAS_API_KEY }
                });

                const asaasStatus = response.data.status;
                // Asaas statuses: 'RECEIVED', 'CONFIRMED', 'OVERDUE', 'PENDING'

                if (asaasStatus === 'RECEIVED' || asaasStatus === 'CONFIRMED') {
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
    } catch (err) {
        console.error("Polling Job Error:", err);
    }
}

// Run polling every 10 seconds (faster updates)
setInterval(checkPendingPayments, 10000);


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
        // If it's Credit Card it might be 'CONFIRMED' already, or 'PENDING'
        // We save whatever status returned.
        const returnedStatus = response.data.status; 
        
        await supabaseAdmin.from('payments').insert({
            user_id: user.id,
            asaas_id: response.data.id,
            amount: price,
            status: returnedStatus, // Could be PENDING or CONFIRMED
            invoice_url: response.data.invoiceUrl
        });

        // 4. IMMEDIATE ACTIVATION CHECK (For Credit Card)
        if (returnedStatus === 'CONFIRMED' || returnedStatus === 'RECEIVED') {
             const { key, planName } = generateLicenseKey(price);

             // Calculate expiry based on plan
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
                .eq('id', user.id);
        }

        return res.json({ 
            paymentId: response.data.id, 
            invoiceUrl: response.data.invoiceUrl,
            pixQrCode: response.data.bankSlipUrl,
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


// Download Route (Mocked security)
app.get('/api/download/loader', (req: Request, res: Response) => {
    // In real app, verify token again before redirecting for download
    res.json({ url: "https://starlix.net/download/loader_v2.exe" });
});

// Start Server
app.listen(port, () => {
    console.log(`Backend Server running on port ${port}`);
});
