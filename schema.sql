```sql
-- Create a table for public profiles if it doesn't exist
create table if not exists profiles (
  id uuid references auth.users not null primary key,
  email text,
  plan text default 'Free',
  status text default 'Inactive',
  hwid text,
  license_key text,
  asaas_customer_id text,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone,
  last_login timestamp with time zone,
  last_hwid_reset timestamp with time zone
);

-- Set up Row Level Security (RLS)
alter table profiles enable row level security;

-- Policies (Drop first to avoid errors if re-running)
drop policy if exists "Users can view own profile" on profiles;
create policy "Users can view own profile" on profiles
  for select using (auth.uid() = id);

drop policy if exists "Users can update own profile" on profiles;
create policy "Users can update own profile" on profiles
  for update using (auth.uid() = id);

-- Function to handle new user signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, plan, status, hwid, license_key, expires_at)
  values (new.id, new.email, 'Free', 'Inactive', NULL, 'NO-LICENSE', null)
  on conflict (id) do nothing; -- Prevent error if profile exists
  return new;
end;
$$ language plpgsql security definer;

-- Trigger (Drop first to avoid errors)
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Payments Table
create table if not exists payments (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users not null,
  asaas_id text,
  amount decimal,
  status text,
  invoice_url text,
  created_at timestamp with time zone default now()
);

-- Subscriptions Table
create table if not exists subscriptions (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users not null unique,
  asaas_subscription_id text,
  status text,
  next_due_date timestamp with time zone,
  created_at timestamp with time zone default now()
);

-- RLS for Payments
alter table payments enable row level security;
create policy "Users can view own payments" on payments
  for select using (auth.uid() = user_id);

-- RLS for Subscriptions
alter table subscriptions enable row level security;
create policy "Users can view own subscription" on subscriptions
  for select using (auth.uid() = user_id);
