-- 1) Tables
create table if not exists public.votes (
  poll text not null, name text not null, data jsonb not null,
  updated_at timestamptz default now(), primary key (poll, name));
create table if not exists public.proposals (
  poll text not null, name text not null, created_at timestamptz default now(),
  primary key (poll, name));
alter table public.votes enable row level security;
alter table public.proposals enable row level security;

-- 2) Mot de passe du groupe (REMPLACE MOT-DE-PASSE-LONG ; relance cette ligne pour le changer)
create table if not exists public.polls (poll text primary key, pass_hash text not null);
alter table public.polls enable row level security;
revoke all on public.polls from anon, authenticated;
insert into public.polls values ('soiree-1', encode(sha256(convert_to('MOT-DE-PASSE-LONG','utf8')),'hex'))
  on conflict (poll) do update set pass_hash = excluded.pass_hash;

-- 3) Fermer l'accès direct aux tables
drop policy if exists "lecture" on public.votes;
drop policy if exists "ajout" on public.votes;
drop policy if exists "modif" on public.votes;
drop policy if exists "lecture" on public.proposals;
drop policy if exists "ajout" on public.proposals;
revoke all on public.votes, public.proposals from anon, authenticated;

-- 4) Fonctions protégées par le mot de passe
create or replace function public.chk(p_poll text, p_pass text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.polls where poll = p_poll
    and pass_hash = encode(sha256(convert_to(p_pass,'utf8')),'hex')) $$;
revoke execute on function public.chk(text,text) from public, anon, authenticated;

create or replace function public.get_votes(p_poll text, p_pass text) returns setof jsonb
language plpgsql security definer set search_path = '' as $$
begin if not public.chk(p_poll,p_pass) then raise exception 'bad passphrase'; end if;
  return query select data from public.votes where poll = p_poll; end $$;

create or replace function public.get_vote(p_poll text, p_pass text, p_name text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin if not public.chk(p_poll,p_pass) then raise exception 'bad passphrase'; end if;
  return (select data from public.votes where poll = p_poll and name = lower(p_name)); end $$;

create or replace function public.submit_vote(p_poll text, p_pass text, p_name text, p_data jsonb) returns void
language plpgsql security definer set search_path = '' as $$
begin if not public.chk(p_poll,p_pass) then raise exception 'bad passphrase'; end if;
  insert into public.votes(poll,name,data,updated_at) values (p_poll, lower(left(p_name,30)), p_data, now())
  on conflict (poll,name) do update set data = excluded.data, updated_at = now(); end $$;

create or replace function public.get_proposals(p_poll text, p_pass text) returns setof text
language plpgsql security definer set search_path = '' as $$
begin if not public.chk(p_poll,p_pass) then raise exception 'bad passphrase'; end if;
  return query select name from public.proposals where poll = p_poll order by created_at; end $$;

create or replace function public.add_proposal(p_poll text, p_pass text, p_name text) returns void
language plpgsql security definer set search_path = '' as $$
begin if not public.chk(p_poll,p_pass) then raise exception 'bad passphrase'; end if;
  insert into public.proposals(poll,name) values (p_poll, left(p_name,60)) on conflict do nothing; end $$;

-- 5) Droits d'exécution : uniquement les 5 fonctions publiques pour anon
revoke execute on function public.get_votes(text,text), public.get_vote(text,text,text),
  public.submit_vote(text,text,text,jsonb), public.get_proposals(text,text), public.add_proposal(text,text,text) from public;
grant execute on function public.get_votes(text,text), public.get_vote(text,text,text),
  public.submit_vote(text,text,text,jsonb), public.get_proposals(text,text), public.add_proposal(text,text,text) to anon;
