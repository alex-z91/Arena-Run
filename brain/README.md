# Arena Brain — Ambiente de testes

Este diretório contém a prévia visual administrativa. **Não inclui autenticação Master**, operações administrativas ou dados reais.

Branch de trabalho: `feat/arena-brain` em `alex-z91/Arena-Run`.

Para publicar `brain.alexcoder.space` sem afetar o GitHub Pages dos atletas, é necessário um repositório GitHub separado, por exemplo `alex-z91/Arena-Brain`. GitHub Pages não permite dois sites e dois domínios independentes no mesmo repositório.

Ao criar o novo repositório, copie `brain/index.html` para `index.html`, `brain/CNAME` para `CNAME`, e o workflow `brain/pages-workflow.yml` para `.github/workflows/pages.yml`; então em **Settings → Pages** selecione **GitHub Actions**. No DNS da GoDaddy, CNAME `brain` → `alex-z91.github.io` (não `alexcoder.space`). Habilite **Enforce HTTPS** quando o certificado estiver emitido. Se a pasta do Brain passar a ser a raiz do novo repositório, use branch própria de desenvolvimento para as próximas alterações.

O subdomínio não protege a administração. Não habilite rotas administrativas antes de implementar autenticação reforçada e validação RBAC do servidor.
