# PBS Net API

![Node.js](https://img.shields.io/badge/Node.js-18.x-green) ![Express.js](https://img.shields.io/badge/Express.js-4.x-blue) ![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-brightgreen) ![License](https://img.shields.io/badge/License-MIT-yellow)

এটি একটি RESTful API যা পল্লী বিদ্যুৎ সমিতি (PBS) এর অভ্যন্তরীণ ব্যবহারকারীদের জন্য নোট তৈরি, শেয়ারিং এবং অনুমতি ব্যবস্থাপনার জন্য ডিজাইন করা হয়েছে।

---

## 🚀 ফিচারসমূহ (Features)

* **ব্যবহারকারী ব্যবস্থাপনা:**
    * ইমেইল/মোবাইল নম্বর ও পাসওয়ার্ড দিয়ে রেজিস্ট্রেশন ও লগইন।
    * JWT (JSON Web Token) ভিত্তিক নিরাপদ প্রমাণীকরণ।
    * পাসওয়ার্ড রিসেট ও পরিবর্তন করার সুবিধা।
    * ব্যবহারকারীর প্রোফাইল তৈরি এবং আপডেট।
    * অন্য ব্যবহারকারীকে মোবাইল নম্বর বা ID দিয়ে খোঁজার ব্যবস্থা।

* **নোট ব্যবস্থাপনা:**
    * যেকোনো লগইন করা ব্যবহারকারী নোট তৈরি করতে পারেন।
    * প্রতিটি নোটের জন্য একটি ইউনিক ৮-ডিজিটের আইডি তৈরি হয়।
    * নোটের মূল ডেটা JSON ফরম্যাটে সংরক্ষণ করা হয়।

* **ভূমিকা ও অনুমতি (Roles & Permissions):**
    * প্রতিটি নোটের জন্য দুটি ভূমিকা: **Admin** এবং **Viewer**।
    * নোটের অ্যাডমিন অন্য ব্যবহারকারীকে নোটে যুক্ত করতে, বাদ দিতে এবং তাদের ভূমিকা পরিবর্তন করতে পারেন।
    * নোটের শেষ অ্যাডমিনকে বাদ দেওয়া যাবে না।

* **ড্যাশবোর্ড ও ইন্টার‍্যাকশন:**
    * ব্যবহারকারী তার অনুমতি থাকা সমস্ত নোটের তালিকা দেখতে পারেন।
    * নিজের PBS-এর অধীনে থাকা সমস্ত নোটের তালিকা দেখা যায় (অনুমতি না থাকলে মূল ডেটা দেখা যায় না)।
    * যেকোনো নোটে **Viewer** হওয়ার জন্য অনুরোধ পাঠানোর সিস্টেম।
    * নোটের অ্যাডমিন ভিউয়ার রিকোয়েস্ট গ্রহণ বা প্রত্যাখ্যান করতে পারেন।

---

## 💻 ব্যবহৃত প্রযুক্তি (Technology Stack)

* **ফ্রেমওয়ার্ক:** Node.js, Express.js
* **ডাটাবেস:** Supabase (PostgreSQL)
* **প্রমাণীকরণ:** JSON Web Token (JWT)
* **পাসওয়ার্ড হ্যাশিং:** Bcrypt.js
* **ইমেইল সার্ভিস:** Nodemailer

---

## 🔧 সেটআপ এবং ইন্সটলেশন (Setup and Installation)

প্রজেক্টটি আপনার লোকাল মেশিনে চালানোর জন্য নিচের ধাপগুলো অনুসরণ করুন।

### পূর্বশর্ত (Prerequisites)
* [Node.js](https://nodejs.org/) (v16 বা নতুন)
* [Git](https://git-scm.com/)
* একটি [Supabase](https://supabase.com/) অ্যাকাউন্ট

### ধাপসমূহ

১. **রিপোজিটরিটি ক্লোন করুন:**
   ```bash
   git clone [https://github.com/your-username/pbs-net-api.git](https://github.com/your-username/pbs-net-api.git)
   cd pbs-net-api
   ```

২. **NPM প্যাকেজগুলো ইন্সটল করুন:**
   ```bash
   npm install
   ```

৩. **Supabase সেটআপ:**
   * Supabase-এ একটি নতুন প্রজেক্ট তৈরি করুন।
   * প্রজেক্টের **SQL Editor**-এ গিয়ে `schema.sql` ফাইলের কোডটি রান করে ডাটাবেস টেবিলগুলো তৈরি করুন।
   * আপনার প্রজেক্টের **Settings > API** থেকে `Project URL` এবং `anon key` সংগ্রহ করুন।

৪. **এনভায়রনমেন্ট ভেরিয়েবল সেটআপ:**
   প্রজেক্টের মূল ফোল্ডারে `.env.example` ফাইলটিকে কপি করে `.env` নামে একটি নতুন ফাইল তৈরি করুন। এরপর নিচের তথ্যগুলো পূরণ করুন:

   ```env
   # Supabase Credentials
   SUPABASE_URL=YOUR_SUPABASE_PROJECT_URL
   SUPABASE_KEY=YOUR_SUPABASE_ANON_KEY

   # API Configuration
   JWT_SECRET=YOUR_SUPER_SECRET_AND_STRONG_JWT_KEY
   PORT=3000

   # Email Server (Gmail) Configuration
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-16-character-gmail-app-password
   ```
   ⚠️ **গুরুত্বপূর্ণ:** `.gitignore` ফাইলে `.env` যুক্ত করা আছে, তাই আপনার গোপন কী কখনো GitHub-এ আপলোড হবে না।

---

## ▶️ অ্যাপ্লিকেশন চালানো (Running the Application)

আপনার টার্মিনালে নিচের কমান্ডটি রান করুন:
```bash
node server.js
```
সার্ভারটি ডিফল্টভাবে `http://localhost:3000` পোর্টে চালু হবে।

---

## 🔗 এপিআই এন্ডপয়েন্টসমূহ (API Endpoints)

এখানে এপিআই-এর প্রধান এন্ডপয়েন্টগুলোর একটি সংক্ষিপ্ত তালিকা দেওয়া হলো। বিস্তারিত তথ্যের জন্য `documentation.html` ফাইলটি দেখুন।

| Endpoint                        | Method | বিবরণ                                   | Access  |
| ------------------------------- | :----: | ---------------------------------------- | :-----: |
| **ব্যবহারকারী ও প্রমাণীকরণ** |        |                                          |         |
| `/auth/register`                | `POST` | নতুন ব্যবহারকারী রেজিস্টার করা             | Public  |
| `/auth/login`                   | `POST` | ব্যবহারকারীকে লগইন করানো                 | Public  |
| `/auth/forgot-password`         | `POST` | পাসওয়ার্ড রিসেট লিঙ্ক পাঠানো            | Public  |
| `/users/password`               | `PUT`  | লগইন করা ব্যবহারকারীর পাসওয়ার্ড পরিবর্তন | Private |
| `/users/profile`                | `GET`  | নিজের প্রোফাইল দেখা                     | Private |
| `/users/profile`                | `PUT`  | নিজের প্রোফাইল আপডেট করা                | Private |
| `/users/search`                 | `GET`  | মোবাইল নম্বর দিয়ে ব্যবহারকারী খোঁজা     | Private |
| `/users/:id`                    | `GET`  | User ID দিয়ে ব্যবহারকারী খোঁজা           | Private |
| **নোট ব্যবস্থাপনা** |        |                                          |         |
| `/notes`                        | `POST` | নতুন নোট তৈরি করা                       | Private |
| `/notes/:id`                    | `GET`  | নির্দিষ্ট নোটের বিবরণ দেখা              | Private |
| `/notes/:id`                    | `PUT`  | নির্দিষ্ট নোট আপডেট করা                  | Private |
| `/notes/:id`                    | `DELETE`| নির্দিষ্ট নোট ডিলিট করা                   | Private |
| **ভূমিকা ও অনুমতি** |        |                                          |         |
| `/notes/:id/permissions`        | `POST` | নোটে ব্যবহারকারীকে যুক্ত করা              | Private |
| `/notes/:id/permissions`        | `DELETE`| নোট থেকে ব্যবহারকারীকে বাদ দেওয়া         | Private |
| **ড্যাশবোর্ড ও ইন্টার‍্যাকশন** |        |                                          |         |
| `/dashboard/my-notes`           | `GET`  | আমার নোটের তালিকা দেখা                  | Private |
| `/dashboard/pbs-notes`          | `GET`  | PBS-এর সব নোট দেখা                      | Private |
| **ভিউয়ার রিকোয়েস্ট সিস্টেম** |        |                                          |         |
| `/notes/:id/request-access`     | `POST` | ভিউয়ার হওয়ার অনুরোধ পাঠানো            | Private |
| `/notes/:id/requests`           | `GET`  | পেন্ডিং রিকোয়েস্ট দেখা                  | Private |
| `/notes/requests/:requestId`    | `PUT`  | রিকোয়েস্ট গ্রহণ বা প্রত্যাখ্যান করা       | Private |

---

## 📜 লাইসেন্স (License)

এই প্রজেক্টটি MIT লাইসেন্সের অধীনে প্রকাশিত। বিস্তারিত জানতে `LICENSE` ফাইলটি দেখুন।