// Supabase Edge Function: admin-create-user
// Only an ACTIVE ADMIN can call this. It creates the login using the service-role key,
// which exists only here on the server and never reaches the browser.
import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
const ROLES = ['admin', 'manager', 'worker', 'accountant'];

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  const url = Deno.env.get('SUPABASE_URL')!;
  const caller = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, {
    global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } },
  });
  const { data: { user } } = await caller.auth.getUser();
  if (!user) return json({ error: 'Not signed in' }, 401);
  const { data: role } = await caller.rpc('current_app_role');
  if (role !== 'admin') return json({ error: 'Only administrators can create accounts' }, 403);

  let b: any;
  try { b = await req.json(); } catch { return json({ error: 'Invalid request' }, 400); }
  const email = String(b.email ?? '').trim().toLowerCase();
  const full_name = String(b.full_name ?? '').trim().slice(0, 100);
  const password = String(b.password ?? '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: 'Enter a valid email address' }, 400);
  if (!ROLES.includes(b.role)) return json({ error: 'Choose a valid role' }, 400);
  if (password.length < 12) return json({ error: 'Password must be at least 12 characters' }, 400);

  const admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  const { data, error } = await admin.auth.admin.createUser({
    email, password, email_confirm: true,
    user_metadata: { full_name },
    app_metadata: { role: b.role },      // only the service role can set this; the database trusts it
  });
  if (error) return json({ error: error.message }, 400);
  return json({ id: data.user.id, email });
});
