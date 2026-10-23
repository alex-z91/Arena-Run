# Arena Coach
Aplicação independente para organizadores do Arena Run.

## Instalação
Criar o repositório `alex-z91/Arena-Coach` no GitHub, inicializado com README. Copiar `index.html`, `CNAME`, `.github/workflows/pages.yml` deste diretório `coach/` na branch `feat/arena-coach-bootstrap` do `Arena-Run` para a raiz do novo repositório.

**Branches:** `main` para homologação e `develop` para desenvolvimento.

**Pages:** Settings > Pages > Source = GitHub Actions.

**DNS:** CNAME `coach` → `alex-z91.github.io` na GoDaddy, e HTTPS quando certificado ativo.

A tela inicial é de login e troca obrigatória de senha. O acesso administrativo é criado apenas pelo Arena Brain, não por cadastro público. A API continua em `https://arena-run-api.onrender.com`.

**Importante:** adicionar `https://coach.alexcoder.space` à allowlist CORS da API antes de testes no subdomínio. As permissões são verificadas na API, não pelo domínio.
