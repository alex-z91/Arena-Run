# Arena Run — Plano do módulo Master (V1)

**Estado:** planejamento; sem publicação do painel administrativo.

## Objetivo
Administrar organizadores, publicação de eventos, regras gerais e auditoria, sem expor controles administrativos no frontend público.

## Hosts propostos
- Público: https://arenarun.alexcoder.space
- Master: https://master.arenarun.alexcoder.space
- Organizador: https://organizador.arenarun.alexcoder.space
- API atual: https://arena-run-api.onrender.com (separar rotas /api/master)

Um subdomínio não é uma fronteira de autorização. A API deve verificar permissões independentemente de CORS, hostname ou UI. Preferir deploy privado/independente ao publicar o Master; **não** incluí-lo no GitHub Pages público atual.

## Escopo MVP
1. Login Master separado, sem cadastro público de Master; MFA obrigatório antes de produção.
2. Dashboard com KPIs: organizadores pendentes/ativos/suspensos, eventos em rascunho/revisão/publicados, inscrições pendentes/confirmadas. Indicadores financeiros apenas com origem verificável.
3. Organizações (entidade separada de User): nome fantasia, razão social, documento de identificação apropriado, cidade/UF, contato institucional, status (pending/active/suspended), created_at/updated_at.
4. Membros da organização: organização↔usuário↔papel (owner/admin/operator), revogação de acesso.
5. Aprovações: análise de solicitação, aprovar, rejeitar ou suspender, com motivo e carimbo do operador.
6. Eventos: listar e inspecionar; workflow draft→submitted→approved/published→closed; rejeição retorna para ajustes.
7. Auditoria append-only: actor_id, organization_id, target_type, target_id, action, before/after redigidos, timestamp, request_id.
8. Configuração: política de publicação, taxas e regras básicas; editar apenas com controle de mudanças.

## Limites por função
- Master: visão global e aprovação; atividades sensíveis auditadas.
- Organizador: somente seus eventos, membros e inscrições justificadas.
- Atleta: somente seu perfil e inscrições.
- Proibir autoatribuição de role master/organizer em cadastro público.
- Bloquear acesso de usuários suspensos em cada requisição, inclusive tokens emitidos anteriormente.

## Banco / migrações
Criar `organizations`, `organization_memberships`, `organization_applications`, `event_approval_history` e `audit_events`; adicionar `organization_id` e `publication_status` a `race` de forma migrada. Não usar `db.create_all()` para mudanças incrementais. Preservar relações atuais e fazer backfill dos organizadores e corridas existentes.

## API inicial
- GET /api/master/overview
- GET /api/master/organizations?status=&q=
- GET /api/master/organizations/:id
- POST /api/master/organizations/:id/approve
- POST /api/master/organizations/:id/reject
- POST /api/master/organizations/:id/suspend
- POST /api/master/organizations/:id/reactivate
- GET /api/master/events
- POST /api/master/events/:id/approve
- POST /api/master/events/:id/reject
- GET /api/master/audit?actor=&action=&from=&to=

Não publicar rotas de escrita antes de validação de permissões, rate limit, CSRF se cookies e auditoria.

## Segurança e implantação
- Login administrativo segregado, MFA (preferir WebAuthn/passkey ou TOTP) e bootstrap de Master por procedimento administrativo único.
- Sessão curta e renovação controlada; HttpOnly+Secure+SameSite com CSRF ou outro desenho sólido de autenticação. Evitar credenciais em localStorage.
- CORS allowlist específica por ambiente; CORS não substitui RBAC.
- Proteção de brute force, alertas e revogação de sessões.
- CSP, HSTS, logs com redação de CPF/RG, backups e recuperação.
- Deploy de frontend Master em serviço próprio com acesso não indexado; isolamento de infraestrutura quando viável. Nunca publicar credenciais ou páginas administrativas no _site da Pages pública.
- Proteção de dados pessoais por finalidade, minimização, acesso condicionado e retenção.
- Não habilitar cobrança nem interpretar payment_simulated como pagamento.

## Sequência de execução
F0: congelar contratos atuais, testes de atleta e baseline do banco.
F1: migrações e modelo de organizações/permissões/auditoria.
F2: autenticação Master (MFA) e backend restrito.
F3: interface Master (login, overview, organizações).
F4: aprovação de organizadores e eventos.
F5: deploy separado, testes de isolamento e revisão de segurança.
F6: iniciar módulo Organizador e integrar criação/publicação.

## Critérios de aceite MVP
- Apenas Master autorizado entra no painel.
- O Master aprova/suspende organizadores e a ação fica auditada.
- Organizador suspenso perde acesso às rotas protegidas.
- Eventos não entram no catálogo sem aprovação conforme política definida.
- Atleta não acessa nenhuma rota Master; organizador não visualiza dados de outras organizações.
- Testes de autorização, sessões expiradas, CORS, recuperação após falha e auditoria aprovados.
