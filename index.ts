import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const ADMIN_ROLES = ['owner', 'master_admin', 'admin']

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    )

    // Eingeloggten Nutzer prüfen
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Nicht autorisiert' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 401
      })
    }

    const token = authHeader.replace('Bearer ', '')
    const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token)
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Ungültiger Token' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 401
      })
    }

    // Rolle des anfragenden Nutzers prüfen
    const { data: callerRole } = await supabaseAdmin
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .single()

    if (!callerRole || !ADMIN_ROLES.includes(callerRole.role)) {
      return new Response(JSON.stringify({ error: 'Keine Berechtigung' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403
      })
    }

    const body = await req.json()
    const { action, user_id, role, password } = body

    // GET OWN – eigene Rolle laden (kein Admin nötig)
    if (action === 'getOwn') {
      return new Response(JSON.stringify({ role: callerRole.role }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // GET ALL – alle Rollen laden
    if (action === 'getAll') {
      const { data, error } = await supabaseAdmin
        .from('user_roles')
        .select('*')
        .order('created_at')
      if (error) throw error

      // E-Mails aus auth.users laden
      const { data: { users }, error: usersError } = await supabaseAdmin.auth.admin.listUsers()
      const emailMap: Record<string, string> = {}
      if(!usersError && users){
        users.forEach((u: any) => { emailMap[u.id] = u.email || '' })
      }

      const dataWithEmail = (data || []).map((r: any) => ({
        ...r,
        email: emailMap[r.user_id] || ''
      }))

      return new Response(JSON.stringify({ data: dataWithEmail }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // GET EMAIL – einzelne E-Mail laden
    if (action === 'getEmail') {
      const { data: { user: authUser }, error: userErr } = await supabaseAdmin.auth.admin.getUserById(user_id)
      if(userErr || !authUser) throw new Error('User nicht gefunden')
      return new Response(JSON.stringify({ email: authUser.email || '' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // SET PASSWORD – Passwort direkt setzen
    if (action === 'setPassword') {
      const { error: pwErr } = await supabaseAdmin.auth.admin.updateUserById(user_id, { password })
      if(pwErr) throw pwErr
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // GENERATE RECOVERY LINK – Passwort-Reset-Link für Mitarbeiter erzeugen
    if (action === 'generateRecoveryLink') {
      const { email, redirectTo } = body
      if (!email) {
        return new Response(JSON.stringify({ error: 'E-Mail fehlt' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400
        })
      }
      const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
        type: 'recovery',
        email,
        options: { redirectTo: redirectTo || 'https://curenio.de/nicode_login.html' }
      })
      if (linkErr) throw linkErr
      return new Response(JSON.stringify({ link: linkData.properties.action_link }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // UPDATE – Rolle ändern (nur Owner darf owner vergeben)
    if (action === 'update') {
      if (role === 'owner' && callerRole.role !== 'owner') {
        return new Response(JSON.stringify({ error: 'Nur Owner darf Owner-Rolle vergeben' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403
        })
      }
      const { error } = await supabaseAdmin
        .from('user_roles')
        .update({ role })
        .eq('user_id', user_id)
      if (error) throw error
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // DELETE – Nutzer entfernen (kann sich nicht selbst löschen)
    if (action === 'delete') {
      if (user_id === user.id) {
        return new Response(JSON.stringify({ error: 'Kann sich nicht selbst löschen' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403
        })
      }
      const { error } = await supabaseAdmin
        .from('user_roles')
        .delete()
        .eq('user_id', user_id)
      if (error) throw error
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    return new Response(JSON.stringify({ error: 'Unbekannte Aktion' }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400
    })

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500
    })
  }
})