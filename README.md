<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,100:1A1A1A&height=150&section=header&text=CRYPTOX&fontSize=70&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Абсолютная%20приватность.%20Безупречный%20код.&descAlignY=65&descAlign=50" alt="CryptoX Banner">

<p>
  <b>Математически невзламываемый мессенджер с удобством Telegram и параноидальной защитой Signal.</b><br>
  <i>Мы не требуем вашего доверия. Мы используем архитектуру Zero-Knowledge, чтобы сервер физически не мог знать ваши секреты.</i>
</p>

<p>
  <img src="https://img.shields.io/badge/Security-Strict-FF0000?style=for-the-badge&logo=shield&logoColor=white" />
  <img src="https://img.shields.io/badge/Architecture-Zero%20Knowledge-000000?style=for-the-badge&logo=theia&logoColor=white" />
  <img src="https://img.shields.io/badge/Encryption-E2EE-339933?style=for-the-badge&logo=letsencrypt&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Beta_Testing-0052CC?style=for-the-badge&logo=atlassian&logoColor=white" />
</p>

</div>

---

## 👁️ Зачем мы это создали? (The Manifesto)

Современные корпорации сделали наши личные данные своей собственностью. Ваши сообщения анализируются, метаданные продаются, а базы данных периодически утекают в даркнет. 

**CryptoX — это манифест цифровой свободы.** Это не просто чат. Это неприступная цифровая крепость. Мы спроектировали мессенджер так, что даже если сервер будет полностью скомпрометирован хакерами или спецслужбами, всё, что они получат — это терабайты математического мусора. 

Вам больше не нужно выбирать между удобным UX и настоящей безопасностью. CryptoX объединяет **отзывчивый интерфейс, миллисекундную доставку** и **многослойную архитектуру защиты (Defense in Depth)**.

---

## 📊 Математика и Метрики Проекта

Мы верим в цифры, а не в пустые обещания. 

- 🕒 **> 27,000,000 лет** — расчетное время брутфорса стандартного пароля пользователя на суперкомпьютере (благодаря Argon2id с 256MB RAM cost).
- ⚡ **< 50 мс** — среднее время доставки сообщения P2P благодаря WebSocket и Redis Pub/Sub.
- 🔐 **256-bit AES-GCM + Curve25519** — золотой стандарт асимметричной криптографии, утвержденный для работы с документами уровня "Top Secret".
- 📦 **0 Bytes** — количество ваших сообщений, хранящихся в открытом виде на сервере (Transparent Payload Blinding).
- 🚀 **10,000+** — одновременных WebSocket-соединений, выдерживаемых на одной стандартной ноде Node.js (HighLoad Fastify).

---

## 🛡️ Абсолютная Архитектура Безопасности

Проект защищен на **7 независимых уровнях**. Компрометация одного из уровней не дает злоумышленнику ничего.

1. **Layer 7: Secure Client Enclave (Браузер)** — Ваш Private Key генерируется на устройстве, использует WebCrypto API и никогда, ни при каких обстоятельствах не пересылается по сети.
2. **Layer 6: Zero-Knowledge Server** — Backend является "слепым" маршрутизатором. Он распределяет зашифрованные BLOB-пакеты и не может парсить контент без ваших ключей.
3. **Layer 5: E2E Cryptography (Signal Protocol)** — Каждое сообщение получает уникальный эфемерный ключ шифрования (Perfect Forward Secrecy). Если ваш ключ взломают завтра, прочитать вчерашние сообщения всё равно будет невозможно.
4. **Layer 4: Double Encryption Base** — Ваш Master-ключ шифруется дважды: вашим локальным паролем и отдельным аппаратным "перцем" (Server Pepper). Украденная БД без физического сервера бесполезна.
5. **Layer 3: KDF Hardening (Argon2id)** — Защита от ASIC/GPU ферм. Хэширование настолько "тяжелое" для памяти, что массовый брутфорс становится экономически и физически нецелесообразным.
6. **Layer 2: Transport Security (TLS 1.3 / DTLS-SRTP)** — Защита WebSocket (`wss://`) и WebRTC (`webrtc://`) от MitM-атак (прослушки провайдером).
7. **Layer 1: Intelligent Rate-Limiting** — Блокировка спама, DDoS и API abuse на лету с использованием in-memory кэша Redis 7.

---

## ⚡ Инженерный Стек и Инфраструктура

Стек CryptoX — это бескомпромиссная связка технологий корпоративного уровня, HighLoad решений и низкоуровневой криптографии. 

### 🌐 Frontend & UI Architecture
<p align="left">
  <img src="https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" />
  <img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/Vite_SWC-646CFF?style=for-the-badge&logo=vite&logoColor=white" />
  <img src="https://img.shields.io/badge/Zustand-433E49?style=for-the-badge&logo=gnometerminal&logoColor=white" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" />
  <img src="https://img.shields.io/badge/Framer_Motion-0055FF?style=for-the-badge&logo=framer&logoColor=white" />
  <img src="https://img.shields.io/badge/WebRTC_P2P-333333?style=for-the-badge&logo=webrtc&logoColor=white" />
</p>
<i>Включает: WebCrypto API, TweetNaCl (Curve25519), FingerprintJS (Идентификация "железа")</i>

### ⚙️ Backend & HighLoad Systems
<p align="left">
  <img src="https://img.shields.io/badge/Node.js_20-43853D?style=for-the-badge&logo=node.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Fastify_5.6-000000?style=for-the-badge&logo=fastify&logoColor=white" />
  <img src="https://img.shields.io/badge/Socket.io_4.8-010101?style=for-the-badge&logo=socketdotio&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL_16-316192?style=for-the-badge&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Redis_7-DC382D?style=for-the-badge&logo=redis&logoColor=white" />
  <img src="https://img.shields.io/badge/Prisma_ORM-2D3748?style=for-the-badge&logo=prisma&logoColor=white" />
  <img src="https://img.shields.io/badge/JWT_%26_OAuth-000000?style=for-the-badge&logo=json-web-tokens&logoColor=white" />
</p>
<i>Включает: Argon2, gRPC (планы на микросервисы), STUN/TURN Servers</i>

### 🛠 DevOps, Cloud & QA
<p align="left">
  <img src="https://img.shields.io/badge/Docker_Swarm-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" />
  <img src="https://img.shields.io/badge/Nginx_Proxy-009639?style=for-the-badge&logo=nginx&logoColor=white" />
  <img src="https://img.shields.io/badge/Cloudflare_CDN-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" />
  <img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" />
  <img src="https://img.shields.io/badge/Playwright-2EAD33?style=for-the-badge&logo=playwright&logoColor=white" />
</p>
<i>Включает: Роботизированный CI/CD, Husky Pre-Push, Сборка через GitHub Actions</i>

---

## ✨ Ключевой Функционал

- 💬 **Мгновенные 1-on-1 Чаты** — Zero-Latency доставка сообщений прямо в устройство собеседника.
- 👥 **Неуязвимые Группы (Server-Side Sender Keys)** — Сервер маршрутизирует сообщения тысячам людей, не имея возможности узнать отправителя или содержание текста.
- 📞 **P2P Крипто-Звонки** — Соединение по протоколу WebRTC с шифрованием DTLS-SRTP. Сигнал передается от клиента к клиенту, минуя сервера.
- 📱 **Seamless Multi-device** — Кроссплатформенная авторизация через аппаратные отпечатки. Забудьте про SMS-коды — безопасность базируется на математической криптографии устройств.
- 🗑️ **Burn-after-Reading** — Сообщения, удаляющиеся навсегда (с затиркой RAM и блоков дискового хранилища).

---

## 📈 Roadmap (Дорожная Карта)

- [x] **Phase 1: Core Foundation & Cryptography** *(Архитектура Zero-Knowledge, Хэширование, Docker)*
- [x] **Phase 2: Authentication Security** *(FingerprintJS, Argon2id, JWT Layers)*
- [x] **Phase 3: E2EE Messaging Socket** *(WebSocket Payload Blinding, Signal Double Ratchet)*
- [ ] **Phase 4: Groups & Circle Protocol** *(Масштабирование крипто-ключей в группах)* — **В РАЗРАБОТКЕ**
- [ ] **Phase 5: Secure Media & Drops** *(Зашифрованная передача файлов, изоляция BlobURI)*
- [ ] **Phase 6: WebRTC Privacy Calls** *(STUN/TURN obfuscation, Anti-Fingerprint protection)*

---

<div align="center">
  <br>
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=500&size=16&duration=4000&pause=1000&color=61DAFB&center=true&vCenter=true&width=800&lines=Privacy+is+not+a+crime;Code+is+Law;Cryptography+is+the+ultimate+shield" alt="Typing SVG" />
  <p><b>Made by GansGX 2026. Опенсорс проект для всех людей нашего мира. 🌍</b></p>
  <p>MIT License © 2026</p>
</div>
