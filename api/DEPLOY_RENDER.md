# Implantação segura: Arena Run API

Projeto Neon exclusivo: **Arena-Run** (ID `silent-tree-52059307`). Não publicar usuário/senha do banco.

1. Conecte Render à conta GitHub e importe o repositório `alex-z91/Arena-Run` como Blueprint a partir de `render.yaml`.
2. Confirme o plano selecionado na interface do Render antes de criar recursos pagos.
3. No Render, configure a variável secreta `DATABASE_URL` com a connection string da instância **Arena-Run** no Neon (preferencialmente pooled + SSL). Não grave no Git.
4. O `SECRET_KEY` é gerado pelo Render. Mantenha o segredo estável; trocá-lo invalida sessões.
5. Veja a URL HTTPS do serviço no Render e teste `/api/health`.
6. Só então defina `window.ARENA_API_URL = 'https://<seu-servico-render>.onrender.com'` em `config.js` no GitHub (apenas URL pública; sem credenciais).
7. Confirme que `FRONTEND_ORIGIN` coincide exatamente com `https://arenarun.alexcoder.space`.
8. Execute `python -m unittest discover -s api -p 'test_*.py'` em ambiente isolado. Para rodar localmente: `cd api && python -m unittest test_app.py`.

**Bloqueio para uso público real:** o projeto ainda usa `db.create_all()` na inicialização, não migrations; usa token assinado válido até 12 horas, sem logout no servidor, revogação ou rate limit; não há e-mail verificado, recuperação de senha nem reserva transacional de vagas. Implementar antes do lançamento com dados reais.

**GitHub Pages:** o workflow publica `index.html`, `atleta.html` e `config.js` no domínio `arenarun.alexcoder.space`. Sem URL de API, a área do atleta deve informar que o serviço não está configurado.
