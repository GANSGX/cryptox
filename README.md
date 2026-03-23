<div align="center">

<h1>🔐 CRYPTOX</h1>

<p>
  <b>Абсолютная приватность. Математическая криптография. Удобство мессенджера нового поколения.</b>
</p>

<p>
  <img src="https://img.shields.io/badge/Security-Strict-FF0000?style=for-the-badge&logo=shield&logoColor=white" alt="Security Strict" />
  <img src="https://img.shields.io/badge/Architecture-Zero%20Knowledge-000000?style=for-the-badge&logo=theia&logoColor=white" alt="Zero Knowledge" />
  <img src="https://img.shields.io/badge/Encryption-E2EE-339933?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="E2EE" />
</p>

<p>
  <img src="https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" />
  <img src="https://img.shields.io/badge/Node.js_20-43853D?style=for-the-badge&logo=node.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Fastify-000000?style=for-the-badge&logo=fastify&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white" />
</p>

</div>

---

## 👁️ Философия Проекта (The Manifesto)

В современном мире данные стали главной валютой. Большинство мессенджеров, даже те, которые заявляют о безопасности, имеют возможность читать ваши логи, парсить метаданные и передавать ключи по запросу. 

**CryptoX** создается с одной бескомпромиссной целью: **создать удобный, молниеносный мессенджер, серверы которого физически и математически не способны прочитать ваши сообщения.** 

Это не доверие компании или серверу. Это доверие к математике (Signal Protocol & Curve25519) и архитектуре **Zero-Knowledge (Нулевое разглашение)**. Мы берем бескомпромиссную безопасность Signal, параноидальные практики InfoSec и оборачиваем это в плавный, отзывчивый UX уровня Telegram.

---

## 🛡️ Архитектура Безопасности (Defense in Depth)

Проект защищен на **7 независимых уровнях**. Компрометация одного из уровней не дает злоумышленнику ничего, кроме зашифрованного шума.

### 🌐 The 7-Layer Defense:
1. **Layer 7: Client Enclave** — Ключи шифрования (Master Key, Private Keys) никогда не покидают устройство. Они зашифрованы локально, извлекаются только в оперативной памяти (In-Memory Key Isolation) и привязаны к аппаратному отпечатку браузера (`FingerprintJS`).
2. **Layer 6: Zero-Knowledge Server** — Сервер выполняет исключительно роль маршрутизатора "слепых" пакетов. База данных хранит не сообщения, а математически непригодные для расшифровки бинарные payload-облака.
3. **Layer 5: E2E Cryptography** — Использование асимметричной криптографии на базе **Curve25519** и обмена протоколов ключами (Double Ratchet Algorithm). Каждый новый пакет имеет новый эфемерный ключ шифрования (Perfect Forward Secrecy).
4. **Layer 4: Double Encryption** — Мастер-ключ пользователя зашифрован дважды: ключом, генерируемым из мастер-пароля, и отдельным серверным перцем (Server Pepper). Украденная база данных без ключей пользователей и серверной памяти — бесполезна.
5. **Layer 3: KDF Hardening** — Применение **Argon2id** (настройки: 256MB RAM cost, high iterations). Защита от брутфорса на специализированных GPU и ASIC фермах. Расчетное время подбора 12-символьного пароля суперкомпьютером — более 27 млн лет.
6. **Layer 2: Transport Security** — Строгий **TLS 1.3** и защита соединений WebSocket (`wss://`) от атак Man-in-the-Middle. Подмена сертификатов отслеживается на уровне клиента.
7. **Layer 1: Network & Rate Limiting** — Динамическая защита от DDoS-атак и интеллектуальный Rate-Limiting (на базе Redis) для блокирования спама, брутфорса и API abuse.

---

## ✨ Ключевые Возможности

- 💬 **Peer-to-Peer 1-on-1 Чаты** — Мгновенные сообщения с миллисекундной доставкой по `Socket.io`, обернутые в непробиваемый панцирь **TweetNaCl / Signal Protocol**.
- 👥 **Group Chats (Server-Side E2EE)** — Групповые чаты реализованы через механизм обмена Sender Keys, что позволяет поддерживать скорость доставки без ущерба для приватности каждого участника.
- 📞 **Крипто-Звонки (WebRTC)** — Прямое P2P аудио/видео соединение с шифрованием DTLS-SRTP. Сервера (STUN/TURN) не могут перехватывать голос, так как туннель создается между клиентами напрямую.
- 📱 **Seamless Multi-device** — Умная система авторизации новых устройств: ваш телефон подтверждает вход с планшета через цепочку доверенных ключей авторизации. Никаких sms-кодов, только строгие криптографические подписи.
- 🗑️ **Ephemeral Messaging** — Автоматическое "испаряющееся" удаление сообщений как с устройств, так и из эфемерной базы сервера.

---

## 🔧 Инженерный Стек и Инфраструктура

Мы собрали стек, отвечающий стандартам современных HighLoad и FinTech проектов.

### 💻 Client-Side (Реактивный UX и Криптография)
<p align="left">
  <img src="https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" />
  <img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white" />
  <img src="https://img.shields.io/badge/Zustand-433E49?style=for-the-badge&logo=gnometerminal&logoColor=white" />
  <img src="https://img.shields.io/badge/WebCrypto_API-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" />
</p>
- **Zustand** для реактивного и атомарного шаринга состояний.
- **WebCrypto API & TweetNaCl** для низкоуровневых операций с буферами и открытыми/секретными ключами.
- **FingerprintJS** для продвинутого отслеживания сессий устройств.

### ⚙️ Server-Side (Zero-Knowledge HighLoad Router)
<p align="left">
  <img src="https://img.shields.io/badge/Node.js_20-43853D?style=for-the-badge&logo=node.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Fastify_5.6-000000?style=for-the-badge&logo=fastify&logoColor=white" />
  <img src="https://img.shields.io/badge/Socket.io_4.8-010101?style=for-the-badge&logo=socketdotio&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL_16-316192?style=for-the-badge&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Redis_7-DC382D?style=for-the-badge&logo=redis&logoColor=white" />
</p>
- **Fastify** — выбран вместо Express из-за огромного преимущества в пропускной способности (throughput) и производительности.
- **PostgreSQL 16** — реализация строгих таблиц с абстрактными BLOB полями для зашифрованных сообщений. Ни один символ контекста не парсится сервером.
- **Redis 7** — высокоскоростной кэш для управления WebSocket подключениями (adapter), управления сессиями и жесткого rate-limiting.

### 🛠 DevOps, Cloud & QA
<p align="left">
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" />
  <img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" />
  <img src="https://img.shields.io/badge/Husky_%26_Lint-FCC72B?style=for-the-badge&logo=eslint&logoColor=black" />
</p>
- Строгая CI/CD обвязка (GitHub Actions, Husky pre-push protection).
- Контейнеризация через Docker для изоляции сервисов.
- Планируется масштабирование через Kubernetes (K8s) для авто-роутинга множественных Socket.io нод.

---

## 📈 Roadmap (Дорожная карта)

Проект активно развивается от лабораторного прототипа к полноценному production-ready продукту.

- [x] **Phase 1: Core Foundation & Security** *(CI/CD, Dockerize, Hashing, Zero-Knowledge Architecture Design)*
- [x] **Phase 2: Authentication & Sessions** *(Argon2id, Multi-Device sync basic logic, JWT/Refresh layers)*
- [ ] **Phase 3: E2EE Messaging Delivery** *(Double Ratchet, Message payload blind routing, Read receipts)* -> **IN PROGRESS**
- [ ] **Phase 4: Group & Circles Protocol** *(Управление приватными ключами в группах без раскрытия сервера)*
- [ ] **Phase 5: Secure Media & Files** *(Изоляция файлов в браузере, шифрование блоками, WebM Voice)*
- [ ] **Phase 6: WebRTC Privacy Calls** *(STUN/TURN obfuscation, P2P connection)*

---

<div align="center">
  <br>
  <p><b>Отказ от ответственности: Приватность — базовое право человека.</b><br>Этот проект пишется с глубоким уважением к конфиденциальности коммуникаций и защите инженерных данных.</p>
  <p>Made with ❤️ and 🔐 by Vadim | MIT License © 2025</p>
</div>
