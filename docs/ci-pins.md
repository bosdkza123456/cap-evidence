# Reproducibility pins

Verified on 2026-10-08 using official upstream tag refs and Go release metadata:

- actions/checkout official v4 tag target: 11d5960a326750d5838078e36cf38b85af677262
- actions/setup-go official v5 tag target: 40f1582b2485089dde7abd97c1529aa768e1baff
- Go: 1.26.8
- Go linux-amd64 toolchain archive SHA256: d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b

Sources: https://github.com/actions/checkout , https://github.com/actions/setup-go , https://go.dev/dl/?mode=json . CI consumes immutable action commit references and .go-version; it does not resolve moving tags or stable at runtime. The hosted runner image remains mutable.
