-- 温柔手账小天地：Supabase Free 云同步基础 schema
-- 在你自己创建的 Supabase 项目 SQL Editor 中人工执行；本文件不会自动运行。
-- 设计约定：前端只提交公开字段到 site_state.content；私密条目只进 private_entries。
-- 对本文件创建的 public-schema 表，RLS 与 GRANT 必须同时设置；Storage 另在 Dashboard 配置。

create table if not exists public.site_state (
    id text primary key check (id = 'main'),
    content jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now(),
    constraint site_state_public_payload_only check (
        jsonb_typeof(content) = 'object'
        -- Allow only fields currently emitted by cloudPayload(); unknown top-level fields fail closed.
        and content - array['version', 'pageText', 'img', 'gallery', 'entries', 'theme', 'tab'] = '{}'::jsonb
        -- Explicitly reject private-entry keys anywhere in nested JSON, not only at the root.
        and not jsonb_path_exists(content, '$.**.privateJournal')
        and not jsonb_path_exists(content, '$.**.privateEntries')
        and not jsonb_path_exists(content, '$.**.private_entries')
        -- The entries object is public-only, with just works and journal collections.
        and (
            not (content ? 'entries')
            or (
                jsonb_typeof(content->'entries') = 'object'
                and (content->'entries') - array['works', 'journal'] = '{}'::jsonb
            )
        )
    )
);

create table if not exists public.site_admins (
    user_id uuid primary key references auth.users(id) on delete cascade,
    created_at timestamptz not null default now()
);

create table if not exists public.private_entries (
    id text not null,
    user_id uuid not null references auth.users(id) on delete cascade,
    title text not null default '',
    date text not null default '',
    summary text not null default '',
    body text not null default '',
    tags jsonb not null default '[]'::jsonb check (jsonb_typeof(tags) = 'array'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (user_id, id)
);

create index if not exists private_entries_user_created_idx
    on public.private_entries (user_id, created_at desc);

alter table public.site_state enable row level security;
alter table public.site_admins enable row level security;
alter table public.private_entries enable row level security;

-- 明确撤销 client roles（也包括 PUBLIC）原有的所有表级操作，再只授予所需权限。
-- service_role 不在此处授予；它本身可绕过 RLS，绝不能放在前端。
revoke all on table public.site_state from PUBLIC, anon, authenticated;
revoke all on table public.site_admins from PUBLIC, anon, authenticated;
revoke all on table public.private_entries from PUBLIC, anon, authenticated;

grant usage on schema public to anon, authenticated;

grant select on table public.site_state to anon, authenticated;
grant insert, update, delete on table public.site_state to authenticated;

grant select on table public.site_admins to authenticated;
-- site_admins 不授予 anon 权限，也不授予客户端 insert/update/delete。

grant select, insert, update, delete on table public.private_entries to authenticated;
-- private_entries 不授予 anon 权限。

drop policy if exists site_state_public_read on public.site_state;
drop policy if exists site_state_admin_insert on public.site_state;
drop policy if exists site_state_admin_update on public.site_state;
drop policy if exists site_state_admin_delete on public.site_state;

create policy site_state_public_read
    on public.site_state for select to anon, authenticated
    using (true);

create policy site_state_admin_insert
    on public.site_state for insert to authenticated
    with check (
        exists (
            select 1 from public.site_admins a
            where a.user_id = (select auth.uid())
        )
    );

create policy site_state_admin_update
    on public.site_state for update to authenticated
    using (
        exists (
            select 1 from public.site_admins a
            where a.user_id = (select auth.uid())
        )
    )
    with check (
        exists (
            select 1 from public.site_admins a
            where a.user_id = (select auth.uid())
        )
    );

create policy site_state_admin_delete
    on public.site_state for delete to authenticated
    using (
        exists (
            select 1 from public.site_admins a
            where a.user_id = (select auth.uid())
        )
    );

drop policy if exists site_admins_read_self on public.site_admins;
create policy site_admins_read_self
    on public.site_admins for select to authenticated
    using (user_id = (select auth.uid()));
-- Non-recursive whitelist check: this table's only policy checks auth.uid() directly.
-- The policies above and below may read site_admins; site_admins policies never read those tables.
-- Seed/edit the whitelist only from the Supabase Dashboard SQL Editor (postgres role).

drop policy if exists private_entries_admin_select_own on public.private_entries;
drop policy if exists private_entries_admin_insert_own on public.private_entries;
drop policy if exists private_entries_admin_update_own on public.private_entries;
drop policy if exists private_entries_admin_delete_own on public.private_entries;

create policy private_entries_admin_select_own
    on public.private_entries for select to authenticated
    using (
        user_id = (select auth.uid())
        and exists (select 1 from public.site_admins a where a.user_id = (select auth.uid()))
    );

create policy private_entries_admin_insert_own
    on public.private_entries for insert to authenticated
    with check (
        user_id = (select auth.uid())
        and exists (select 1 from public.site_admins a where a.user_id = (select auth.uid()))
    );

create policy private_entries_admin_update_own
    on public.private_entries for update to authenticated
    using (
        user_id = (select auth.uid())
        and exists (select 1 from public.site_admins a where a.user_id = (select auth.uid()))
    )
    with check (
        user_id = (select auth.uid())
        and exists (select 1 from public.site_admins a where a.user_id = (select auth.uid()))
    );

create policy private_entries_admin_delete_own
    on public.private_entries for delete to authenticated
    using (
        user_id = (select auth.uid())
        and exists (select 1 from public.site_admins a where a.user_id = (select auth.uid()))
    );

-- Storage is a Supabase-managed schema. Do not ALTER/GRANT/REVOKE storage.objects here:
-- its table owner is platform-managed and hosted SQL Editor may reject ownership changes.
-- Create bucket public-images and its visitor-read / whitelist-admin write policies in
-- Dashboard > Storage after creating and seeding the admin account.

-- 管理员白名单初始 seed（以下只是模板，先在 Authentication > Users 创建用户，再手动执行）：
-- insert into public.site_admins (user_id)
-- select id from auth.users where email = 'YOUR_ADMIN_EMAIL'
-- on conflict (user_id) do nothing;
-- 确认只命中你本人创建的管理账号；不要给 anon/authenticated 授予 site_admins 写权限。

-- 使用要点：
-- 1) anon 只能读取 site_state；不能写公开内容，也不能访问 private_entries。
-- 2) authenticated 即使获得 table GRANT，也必须通过 site_admins 白名单才能写公开内容；
--    private_entries 还必须满足 user_id = auth.uid()。
-- 3) RLS 不代替 GRANT。对本文件创建的 public 表逐项撤销并授予必要权限。
-- 4) 管理员检查只从 policy 查询 site_admins；site_admins 自身 policy 不回查其他业务表，因此不递归。
-- 5) 本文件只创建 public-schema 表与策略；Storage 桶和对象策略在 Supabase Dashboard 配置。
