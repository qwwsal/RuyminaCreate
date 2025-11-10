const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Настройка CORS для продакшена
app.use(cors({
  origin: true, // Разрешаем все домены в продакшене
  credentials: true
}));

// Для парсинга application/json
app.use(express.json());
// Для парсинга application/x-www-form-urlencoded (формы)
app.use(express.urlencoded({ extended: true }));

// ОБНОВЛЕННЫЕ ПУТИ ДЛЯ ПРОДАКШЕНА
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Раздаем статические файлы
app.use('/uploads', express.static(uploadDir));
app.use(express.static(path.join(__dirname, '../frontend'))); // Раздаем фронтенд

// ОБНОВЛЕННЫЙ ПУТЬ К БАЗЕ ДАННЫХ
const dbPath = path.join(__dirname, 'Polina.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT,
    lastName TEXT,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password TEXT NOT NULL,
    isAdmin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS portfolio (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    image_urls TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    short_description TEXT,
    description TEXT,
    price REAL
  )`);
  
  // Создаем таблицу orders с колонкой status
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    service_id INTEGER,
    description TEXT,
    file_urls TEXT,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(service_id) REFERENCES services(id)
  )`);
  
  // Создаем таблицу reviews с колонкой order_id
  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    service_id INTEGER,
    order_id INTEGER,
    text TEXT,
    rating INTEGER CHECK(rating >= 1 AND rating <= 5),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(service_id) REFERENCES services(id),
    FOREIGN KEY(order_id) REFERENCES orders(id)
  )`);
});

// Функция для добавления колонки order_id и обновления существующих отзывов
function updateReviewsTable() {
  db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='reviews'", (err, table) => {
    if (err) {
      console.error('Error checking reviews table:', err);
      return;
    }
    
    if (table) {
      // Таблица существует, проверяем структуру
      db.all(`PRAGMA table_info(reviews)`, (err, columns) => {
        if (err) {
          console.error('Error checking reviews table structure:', err);
          return;
        }
        
        if (columns && Array.isArray(columns)) {
          const hasOrderId = columns.some(col => col.name === 'order_id');
          if (!hasOrderId) {
            // Добавляем колонку order_id
            db.run(`ALTER TABLE reviews ADD COLUMN order_id INTEGER`, (err) => {
              if (err) {
                console.error('Error adding order_id column:', err);
              } else {
                console.log('Successfully added order_id column to reviews table');
                // После добавления колонки обновляем существующие отзывы
                updateExistingReviews();
              }
            });
          } else {
            console.log('order_id column already exists in reviews table');
            // Проверяем и обновляем существующие отзывы
            updateExistingReviews();
          }
        }
      });
    } else {
      console.log('Reviews table does not exist, it will be created with order_id column');
    }
  });
}

// Функция для обновления существующих отзывов (присвоение order_id)
function updateExistingReviews() {
  console.log('Checking for reviews without order_id...');
  
  // Получаем все отзывы без order_id
  db.all(`SELECT * FROM reviews WHERE order_id IS NULL`, (err, reviews) => {
    if (err) {
      console.error('Error fetching reviews without order_id:', err);
      return;
    }
    
    console.log(`Found ${reviews.length} reviews without order_id`);
    
    // Для каждого отзыва пытаемся найти подходящий заказ
    reviews.forEach(review => {
      // Ищем заказ этого пользователя с таким же service_id
      db.get(
        `SELECT id FROM orders WHERE user_id = ? AND service_id = ? LIMIT 1`,
        [review.user_id, review.service_id],
        (err, order) => {
          if (err) {
            console.error('Error finding order for review:', err);
            return;
          }
          
          if (order) {
            // Нашли заказ - обновляем отзыв
            db.run(
              `UPDATE reviews SET order_id = ? WHERE id = ?`,
              [order.id, review.id],
              function(err) {
                if (err) {
                  console.error('Error updating review with order_id:', err);
                } else {
                  console.log(`Updated review ${review.id} with order_id ${order.id}`);
                }
              }
            );
          } else {
            console.log(`No order found for review ${review.id} (user: ${review.user_id}, service: ${review.service_id})`);
          }
        }
      );
    });
  });
}

// Вызываем функцию после создания таблиц
setTimeout(updateReviewsTable, 1000);

// Добавляем endpoint для отладки - просмотр всех отзывов с информацией о заказах
app.get('/debug/reviews', (req, res) => {
  db.all(`
    SELECT 
      reviews.*, 
      users.email as user_email, 
      services.name as service_name,
      orders.id as order_id_from_orders,
      orders.status as order_status
    FROM reviews 
    LEFT JOIN users ON reviews.user_id = users.id 
    LEFT JOIN services ON reviews.service_id = services.id
    LEFT JOIN orders ON reviews.order_id = orders.id
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/register', (req, res) => {
  const { firstName, lastName, email, phone, password } = req.body;
  if (!firstName || !lastName || !email || !phone || !password) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  const isAdmin = email.toLowerCase() === 'polina@mail.ru' ? 1 : 0;

  db.run(
    'INSERT INTO users (firstName, lastName, email, phone, password, isAdmin) VALUES (?, ?, ?, ?, ?, ?)',
    [firstName, lastName, email.toLowerCase(), phone, hashedPassword, isAdmin],
    function (err) {
      if (err) return res.status(400).json({ error: 'Пользователь уже существует' });
      res.json({ success: true, userId: this.lastID });
    }
  );
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Неверный email или пароль' });
    if (!bcrypt.compareSync(password, user.password))
      return res.status(400).json({ error: 'Неверный email или пароль' });
    res.json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      phone: user.phone,
      isAdmin: user.isAdmin,
    });
  });
});

app.get('/profile', (req, res) => {
  const userId = req.query.userId;
  db.get('SELECT id, firstName, lastName, email, phone, isAdmin FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Пользователь не найден' });
    db.all(
      `SELECT orders.*, services.name as service_name
       FROM orders
       LEFT JOIN services ON orders.service_id = services.id
       WHERE orders.user_id = ?`,
      [userId],
      (err2, orders) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ user, orders });
      }
    );
  });
});

app.get('/orders', (req, res) => {
  const userId = req.query.userId;
  const isAdmin = req.query.isAdmin === '1';
  if (isAdmin) {
    db.all(
      'SELECT orders.*, users.email as user_email, services.name as service_name FROM orders LEFT JOIN users ON orders.user_id=users.id LEFT JOIN services ON orders.service_id=services.id',
      [],
      (err, orders) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(orders);
      }
    );
  } else {
    db.all(
      'SELECT orders.*, services.name as service_name FROM orders LEFT JOIN services ON orders.service_id=services.id WHERE orders.user_id = ?',
      [userId],
      (err, orders) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(orders);
      }
    );
  }
});

app.get('/portfolio', (req, res) => {
  db.all('SELECT * FROM portfolio', [], (err, rows) => {
    if (err) {
      console.error('Ошибка при получении портфолио:', err);
      return res.status(500).json({ error: 'Ошибка сервера при загрузке портфолио' });
    }
    res.json(rows);
  });
});

app.post('/portfolio', (req, res, next) => {
  upload.array('image_files', 10)(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      console.error('Multer error:', err);
      return res.status(400).json({ error: `Ошибка загрузки файлов: ${err.message}` });
    } else if (err) {
      console.error('Unknown multer error:', err);
      return res.status(500).json({ error: `Ошибка сервера: ${err.message}` });
    }

    const { userId, title, description } = req.body;

    if (!userId || !title) {
      return res.status(400).json({ error: 'userId и title обязательны' });
    }

    const images = req.files ? req.files.map(file => '/uploads/' + file.filename) : [];

    db.get('SELECT isAdmin FROM users WHERE id = ?', [userId], (err, user) => {
      if (err || !user || user.isAdmin !== 1) {
        return res.status(403).json({ error: 'Доступ запрещён' });
      }

      db.run(
        'INSERT INTO portfolio (user_id, title, description, image_urls) VALUES (?, ?, ?, ?)',
        [userId, title, description || '', JSON.stringify(images)],
        function (err) {
          if (err) {
            console.error('DB insert error:', err);
            return next(err);
          }
          res.json({ success: true, id: this.lastID });
        }
      );
    });
  });
});

// Полная версия с работающим статусом
app.post('/orders', upload.array('files', 10), (req, res) => {
  const { userId, service_id, description } = req.body;

  if (!userId || !service_id) {
    return res.status(400).json({ error: 'userId и service_id обязательны' });
  }

  const files = req.files ? req.files.map(file => '/uploads/' + file.filename) : [];

  // Полная версия со статусом
  db.run(
    'INSERT INTO orders (user_id, service_id, description, file_urls, status) VALUES (?, ?, ?, ?, ?)',
    [userId, service_id, description || '', JSON.stringify(files), 'pending'],
    function(err) {
      if (err) {
        console.error('DB insert order error:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Полная версия обновления статуса
app.patch('/orders/:id/status', (req, res) => {
  const orderId = req.params.id;
  const { status } = req.body;
  if (!['pending', 'completed'].includes(status)) {
    return res.status(400).json({ error: 'Неверный статус' });
  }
  
  db.run('UPDATE orders SET status = ? WHERE id = ?', [status, orderId], function(err) {
    if (err) {
      console.error('DB update order status error:', err);
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Заказ не найден' });
    }
    res.json({ success: true });
  });
});

app.get('/services', (req, res) => {
  db.all('SELECT * FROM services', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/services', (req, res) => {
  const { userId, name, short_description, description, price } = req.body;
  db.get('SELECT isAdmin FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user || user.isAdmin !== 1) return res.status(403).json({ error: 'Доступ запрещён' });
    db.run(
      'INSERT INTO services (name, short_description, description, price) VALUES (?, ?, ?, ?)',
      [name, short_description, description, price],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
      }
    );
  });
});

// Обновленный endpoint для создания отзыва с order_id
app.post('/reviews', (req, res) => {
  const { userId, service_id, order_id, text, rating } = req.body;
  
  // Проверяем, существует ли уже отзыв для этого заказа
  db.get('SELECT id FROM reviews WHERE order_id = ? AND user_id = ?', [order_id, userId], (err, existingReview) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (existingReview) {
      return res.status(400).json({ error: 'Вы уже оставили отзыв на этот заказ' });
    }
    
    db.run(
      'INSERT INTO reviews (user_id, service_id, order_id, text, rating) VALUES (?, ?, ?, ?, ?)',
      [userId, service_id, order_id, text, rating],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ success: true, id: this.lastID });
      }
    );
  });
});

// Обновленный endpoint для получения отзывов с фильтрацией по order_id
app.get('/reviews', (req, res) => {
  const { userId, orderId } = req.query;
  let query = `
    SELECT reviews.*, users.email as user_email, services.name as service_name 
    FROM reviews 
    LEFT JOIN users ON reviews.user_id=users.id 
    LEFT JOIN services ON reviews.service_id=services.id
  `;
  let params = [];

  if (userId && orderId) {
    query += ' WHERE reviews.user_id = ? AND reviews.order_id = ?';
    params = [userId, orderId];
  } else if (userId) {
    query += ' WHERE reviews.user_id = ?';
    params = [userId];
  } else if (orderId) {
    query += ' WHERE reviews.order_id = ?';
    params = [orderId];
  }

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Новый endpoint для получения отзыва по конкретному заказу
app.get('/reviews/order/:orderId', (req, res) => {
  const orderId = req.params.orderId;
  const userId = req.query.userId;
  
  db.get(
    `SELECT reviews.*, users.email as user_email, services.name as service_name 
     FROM reviews 
     LEFT JOIN users ON reviews.user_id=users.id 
     LEFT JOIN services ON reviews.service_id=services.id
     WHERE reviews.order_id = ? AND reviews.user_id = ?`,
    [orderId, userId],
    (err, review) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(review || null);
    }
  );
});

// Endpoint для обновления отзыва
app.put('/reviews/:id', (req, res) => {
  const reviewId = req.params.id;
  const { text, rating } = req.body;
  
  db.run(
    'UPDATE reviews SET text = ?, rating = ? WHERE id = ?',
    [text, rating, reviewId],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Отзыв не найден' });
      }
      res.json({ success: true });
    }
  );
});

// Глобальный обработчик ошибок
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(err.status || 500).json({ error: err.message || 'Внутренняя ошибка сервера' });
});

// ИСПРАВЛЕНО: Конкретные маршруты для всех страниц вместо проблемного '*'
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/MainPage.html'));
});

app.get('/MainPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/MainPage.html'));
});

app.get('/ServicePage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/ServicePage.html'));
});

app.get('/PortfolioPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/PortfolioPage.html'));
});

app.get('/ReviewsPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/ReviewsPage.html'));
});

app.get('/AddOrderPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/AddOrderPage.html'));
});

app.get('/AdministratorPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/AdministratorPage.html'));
});

app.get('/AutorizationPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/AutorizationPage.html'));
});

app.get('/ProfilePage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/ProfilePage.html'));
});

app.get('/RegisterPage.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/RegisterPage.html'));
});

// Запуск сервера с указанием хоста
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started on port ${PORT}`);
});