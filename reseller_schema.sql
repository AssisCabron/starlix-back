ALTER TABLE profiles
ADD COLUMN IF NOT EXISTS is_reseller BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS reseller_balance DECIMAL(10, 2) DEFAULT 0.00,
ADD COLUMN IF NOT EXISTS reseller_total_sales DECIMAL(10, 2) DEFAULT 0.00,
ADD COLUMN IF NOT EXISTS asaas_customer_id TEXT;

-- Create reseller_purchases table
CREATE TABLE IF NOT EXISTS reseller_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reseller_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    plan_type TEXT NOT NULL CHECK (plan_type IN ('Daily', 'Monthly', 'Yearly', 'Lifetime')),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_cost DECIMAL(10, 2) NOT NULL,
    total_cost DECIMAL(10, 2) NOT NULL,
    payment_id TEXT, -- Asaas payment ID
    payment_status TEXT DEFAULT 'pending' CHECK (payment_status IN ('pending', 'confirmed', 'failed')),
    keys_generated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create reseller_keys table
CREATE TABLE IF NOT EXISTS reseller_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reseller_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    license_key TEXT UNIQUE NOT NULL,
    plan_type TEXT NOT NULL CHECK (plan_type IN ('Daily', 'Monthly', 'Yearly', 'Lifetime')),
    status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'sold', 'activated')),
    sold_to_user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    sold_at TIMESTAMP WITH TIME ZONE,
    sale_price DECIMAL(10, 2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create withdrawal_requests table
CREATE TABLE IF NOT EXISTS withdrawal_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reseller_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL CHECK (amount > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'completed')),
    pix_key TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_reseller_purchases_reseller_id ON reseller_purchases(reseller_id);
CREATE INDEX IF NOT EXISTS idx_reseller_keys_reseller_id ON reseller_keys(reseller_id);
CREATE INDEX IF NOT EXISTS idx_reseller_keys_status ON reseller_keys(status);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_reseller_id ON withdrawal_requests(reseller_id);
CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status ON withdrawal_requests(status);

-- Enable Row Level Security (RLS)
ALTER TABLE reseller_purchases ENABLE ROW LEVEL SECURITY;
ALTER TABLE reseller_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE withdrawal_requests ENABLE ROW LEVEL SECURITY;

-- RLS Policies for reseller_purchases
CREATE POLICY "Resellers can view their own purchases"
    ON reseller_purchases FOR SELECT
    USING (auth.uid() = reseller_id);

-- RLS Policies for reseller_keys
CREATE POLICY "Resellers can view their own keys"
    ON reseller_keys FOR SELECT
    USING (auth.uid() = reseller_id);

-- RLS Policies for withdrawal_requests
CREATE POLICY "Resellers can view their own withdrawal requests"
    ON withdrawal_requests FOR SELECT
    USING (auth.uid() = reseller_id);

CREATE POLICY "Resellers can create withdrawal requests"
    ON withdrawal_requests FOR INSERT
    WITH CHECK (auth.uid() = reseller_id);
-- Function to increment reseller sales volume
CREATE OR REPLACE FUNCTION increment_reseller_sales(reseller_id_val UUID, amount_val DECIMAL)
RETURNS VOID AS $$
BEGIN
    UPDATE profiles
    SET reseller_total_sales = reseller_total_sales + 1
    WHERE id = reseller_id_val;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
