# AGENTS.md

## Lint and Typecheck

```
npm run lint           # tsc --noEmit — run before every commit
```

Tests:
```
npm test                # node --import tsx --test (all tests)
npm run test:unit       # vitest run (all tests under Vitest)
```

ML subsystem only:
```
npx vitest run tests/ml-*.test.ts --no-coverage --reporter=verbose
```
