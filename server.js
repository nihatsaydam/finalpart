// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');

const app = express();

// Otel adı ve veritabanı adını environment variable'lardan al (varsayılan değerler ile)
const HOTEL_NAME = process.env.HOTEL_NAME || 'Default Hotel';
const DB_NAME = process.env.DB_NAME || 'GreenP';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'nihat.saydam@icloud.com';

console.log(`Starting server for hotel: ${HOTEL_NAME}`);
console.log(`Using database: ${DB_NAME}`);
console.log(`Admin email: ${ADMIN_EMAIL}`);

// ===== User ve ActivityLog modelleri (MongoDB bağlantısından ÖNCE tanımlanıyor) =====
// User (Kullanıcı) modeli
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    trim: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  permissions: {
    bellboy: { type: Boolean, default: false },
    complaints: { type: Boolean, default: false },
    technical: { type: Boolean, default: false },
    laundry: { type: Boolean, default: false },
    roomservice: { type: Boolean, default: false },
    concierge: { type: Boolean, default: false },
    housekeeping: { type: Boolean, default: false },
    spa: { type: Boolean, default: false },
    admin: { type: Boolean, default: false }
  },
  createdBy: { 
    type: String, 
    required: true 
  },
  hotelName: { 
    type: String, 
    default: HOTEL_NAME 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Kullanıcı adı ve otel adı kombinasyonu için bileşik benzersiz indeks
userSchema.index({ username: 1, hotelName: 1 }, { unique: true });

// Şifre şifreleme (hashleme) middleware'i
userSchema.pre('save', async function(next) {
  // Şifre değişmediyse işlemi atla
  if (!this.isModified('password')) return next();
  
  try {
    // Salt oluştur ve şifreyi hashleme
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// ActivityLog (İşlem Günlüğü) modeli
const activityLogSchema = new mongoose.Schema({
  action: { 
    type: String, 
    required: true 
  },
  username: { 
    type: String, 
    required: true 
  },
  details: { 
    type: Object, 
    default: {} 
  },
  hotelName: { 
    type: String, 
    default: HOTEL_NAME 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
});

const User = mongoose.model('User', userSchema, 'Users');
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema, 'ActivityLogs');

// İşlem kaydı oluşturmak için yardımcı fonksiyon
const logActivity = async (action, username, details = {}) => {
  try {
    const log = new ActivityLog({
      action,
      username,
      details,
      hotelName: HOTEL_NAME
    });
    await log.save();
  } catch (error) {
    console.error('İşlem günlüğü kaydedilemedi:', error);
  }
};

// İlk admin kullanıcısını oluştur
const createInitialAdmin = async () => {
  try {
    console.log(`${HOTEL_NAME} - Admin kullanıcısı oluşturma kontrolü başladı...`);
    const adminExists = await User.findOne({ username: 'admin', hotelName: HOTEL_NAME });
    if (!adminExists) {
      console.log(`${HOTEL_NAME} - Admin kullanıcısı bulunamadı, oluşturuluyor...`);
      const adminUser = new User({
        username: 'admin',
        password: 'hayda',
        permissions: {
          bellboy: true,
          complaints: true,
          technical: true,
          laundry: true, 
          roomservice: true,
          concierge: true,
          housekeeping: true,
          spa: true,
          admin: true
        },
        createdBy: 'system',
        hotelName: HOTEL_NAME
      });
      
      const savedAdmin = await adminUser.save();
      console.log(`Admin kullanıcısı başarıyla oluşturuldu (${HOTEL_NAME}):`, savedAdmin.username);
    } else {
      console.log(`Admin kullanıcısı zaten mevcut (${HOTEL_NAME})`);
    }
  } catch (error) {
    console.error(`Admin oluşturma hatası (${HOTEL_NAME}):`, error);
  }
};

// MongoDB Atlas bağlantısı
mongoose
  .connect(
    `mongodb+srv://nihatsaydam13131:nihat1234@keepsty.hrq40.mongodb.net/${DB_NAME}?retryWrites=true&w=majority`
  )
  .then(() => {
    console.log(`Connected to MongoDB Atlas ${DB_NAME} Database!`);
    // Bağlantı başarılı olduktan sonra admin oluşturma işlemini yap
    createInitialAdmin();
  })
  .catch((err) => console.error('Error connecting to MongoDB Atlas:', err));

// Middleware
// Body parser middleware
// Session ayarlarını düzenleyin
app.use(session({
  secret: process.env.SESSION_SECRET || 'keepsty-secure-session-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: `mongodb+srv://nihatsaydam13131:nihat1234@keepsty.hrq40.mongodb.net/${DB_NAME}?retryWrites=true&w=majority`,
    collectionName: 'sessions'
  }),
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24, // 1 gün
    secure: process.env.NODE_ENV === 'production' || sameSite === 'none', // sameSite=none kullanıldığında secure=true olmalı
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // Geliştirme ortamında lax kullanın
  }
}));

// CORS ayarlarını güncelle - credentials desteği ekleyin
app.use(cors({
  origin: true, // Tüm origin'lere izin ver (ya da spesifik domain'leri belirtin)
  credentials: true // Cross-Origin credential (cookie) paylaşımı için gerekli
}));

// SMTP ayarlarınızı buraya ekleyin (örneğin, Gmail, SendGrid, vs.)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // 465 için true, 587 için false
  auth: {
    user: 'keepstyservice@gmail.com',
    pass: 'zxtl ddfk kcot ebki'
  }
});
const housekeepingCleanSchema = new mongoose.Schema({
  cleaningOption: { type: String, required: true },
  username: { type: String, required: true },
  roomNumber: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  status: { 
    type: String, 
    enum: ['waiting', 'active', 'completed'], 
    default: 'waiting' 
  }
});
const HousekeepingClean = mongoose.model('HousekeepingClean', housekeepingCleanSchema, 'housekeepingclean');

// POST endpoint: Yeni temizlik kaydı oluşturma ve e-posta gönderimi
app.post('/save-cleaning-option', async (req, res) => {
  try {
    const { cleaningOption, username, roomNumber, timestamp, status } = req.body;

    const newRecord = new HousekeepingClean({
      cleaningOption,
      username,
      roomNumber,
      timestamp: timestamp || new Date(),
      status: status || 'waiting'
    });

    const savedRecord = await newRecord.save();

    // E-posta içeriğini oluşturma
    const mailOptions = {
      from: `"${HOTEL_NAME} Housekeeping" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,  // Bildirimi almak istediğiniz e-posta adresi
      subject: 'Yeni Temizlik Kaydı Oluşturuldu',
      text: `Yeni bir temizlik kaydı oluşturuldu.
Otel: ${HOTEL_NAME}
Kullanıcı: ${username}
Oda: ${roomNumber}
Temizlik Seçeneği: ${cleaningOption}
Durum: ${status || 'waiting'}
Tarih: ${new Date(timestamp || Date.now()).toLocaleString()}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });

    res.status(201).json(savedRecord);
  } catch (error) {
    console.error("Kayıt oluşturma hatası:", error);
    res.status(500).json({ message: 'Temizlik kaydı oluşturulamadı', error });
  }
});

// GET endpoint: Tüm temizlik kayıtlarını listeleme
app.get('/cleaning-records', async (req, res) => {
  try {
    const records = await HousekeepingClean.find();
    res.json(records);
  } catch (error) {
    console.error("Kayıt getirme hatası:", error);
    res.status(500).json({ message: 'Kayıtlar getirilemedi', error });
  }
});

// PATCH endpoint: Temizlik kaydı durumunu güncelleme (waiting, active, completed)
app.patch('/cleaning-records/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (!['waiting', 'active', 'completed'].includes(status)) {
      return res.status(400).json({ message: 'Geçersiz durum değeri' });
    }
    
    const updatedRecord = await HousekeepingClean.findByIdAndUpdate(id, { status }, { new: true });
    if (!updatedRecord) {
      return res.status(404).json({ message: 'Kayıt bulunamadı' });
    }
    res.json(updatedRecord);
  } catch (error) {
    console.error("Kayıt güncelleme hatası:", error);
    res.status(500).json({ message: 'Kayıt güncellenemedi', error });
  }
});

/* ============================
   Cart Orders Sepet Siparişleri
============================ */
const cartOrderSchema = new mongoose.Schema({
  username: { type: String, required: true },
  roomNumber: { type: String, required: true },
  cartItems: { type: Array, required: true },
  status: { 
    type: String, 
    enum: ['waiting', 'active', 'completed'], 
    default: 'waiting' 
  },
  timestamp: { type: Date, default: Date.now }
});
const CartOrder = mongoose.model('CartOrder', cartOrderSchema, 'cartOrders');


app.post('/save-cart', async (req, res) => {
  try {
    const { username, roomNumber, cartItems } = req.body;
    if (!username || !roomNumber || !cartItems) {
      return res.status(400).json({ message: 'Eksik alanlar var.' });
    }
    // Yeni sipariş oluşturulurken status belirtilmediğinde otomatik olarak "waiting" olacaktır.
    const newCartOrder = new CartOrder({ username, roomNumber, cartItems });
    const savedOrder = await newCartOrder.save();

    // Sepet ürünlerini string haline getir
    const itemsString = cartItems
      .map(item => `${item.name} (Miktar: ${item.quantity}, Fiyat: ${item.price})`)
      .join(', ');

    // E-posta içeriğini oluşturma
    const mailOptions = {
      from: `"${HOTEL_NAME} Cart Orders" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,  // Bildirimi almak istediğiniz e-posta adresi
      subject: 'Yeni Sepet Siparişi Geldi',
      text: `Yeni bir sepet siparişi alındı.
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}
Kullanıcı: ${username}
Ürünler: ${itemsString}
Tarih: ${new Date().toLocaleString()}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });

    res.status(201).json({ message: "Cart saved", result: savedOrder });
  } catch (error) {
    console.error("Error saving cart:", error);
    res.status(500).json({ message: "Error saving cart", error });
  }
});
app.put('/update-cart-status/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const order = await CartOrder.findById(id);
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Mevcut duruma göre sıradaki durumu belirleyelim
    let nextStatus;
    if (order.status === 'waiting') {
      nextStatus = 'active';
    } else if (order.status === 'active') {
      nextStatus = 'completed';
    } else if (order.status === 'completed') {
      return res.status(400).json({ message: "Order is already completed" });
    }

    order.status = nextStatus;
    const updatedOrder = await order.save();
    res.json({ message: "Status updated", order: updatedOrder });
  } catch (error) {
    console.error("Error updating cart status:", error);
    res.status(500).json({ message: "Error updating cart status", error });
  }
});

app.get('/cart-orders', async (req, res) => {
  try {
    const { roomNumber, status } = req.query;
    let query = {};
    if (roomNumber) {
      query.roomNumber = roomNumber;
    }
    if (status) {
      query.status = status;
    }
    const orders = await CartOrder.find(query);
    res.json({ success: true, cartOrders: orders });
  } catch (error) {
    console.error("Cart orders getirme hatası:", error);
    res.status(500).json({ message: "Cart orders getirilemedi", error });
  }
});

/* ======================
   Chat Model & Endpoints
   ====================== */

  // Örnek şema (Tech.js veya server.js içinde)
  const techSchema = new mongoose.Schema({
    roomNumber: { type: String, required: true },
    username: { type: String, required: true, default: 'Unknown' },
    message: { type: String, required: true },
    sender: { type: String, enum: ['user', 'bot'], required: true },
    language: { type: String, default: 'unknown' },
    timestamp: { type: Date, default: Date.now },
    
    // Yeni status alanı: waiting, active veya completed
    status: { type: String, enum: ['waiting', 'active', 'completed'], default: 'waiting' },
  });
  
  const Tech = mongoose.model('Tech', techSchema, 'Tech');
  
  // Tüm oda numaralarına göre gruplandırılmış sohbet kayıtlarını döndüren endpoint
  app.get('/getChatLogse', async (req, res) => {
    try {
      const groupedTech = await Tech.aggregate([
        {
          $group: {
            _id: "$roomNumber",
            messages: { $push: "$$ROOT" },
          },
        },
      ]);
      res.status(200).json(groupedTech);
    } catch (err) {
      console.error('Sohbet kayıtları alınırken hata:', err.message);
      res.status(500).json({ success: false, message: 'Sohbet kayıtları alınırken hata oluştu.' });
    }
  });
  
  // Belirli bir oda numarasına ait sohbet kayıtlarını döndüren endpoint
  app.get('/getChatLogsByRoome/:roomNumber', async (req, res) => {
    try {
      const roomNumber = req.params.roomNumber;
      if (!roomNumber) {
        return res.status(400).json({ success: false, message: 'Oda numarası gerekli.' });
      }
      const techLogs = await Tech.find({ roomNumber }).sort({ timestamp: 1 });
      if (techLogs.length === 0) {
        return res.status(404).json({ success: false, message: 'Bu odaya ait sohbet kaydı bulunamadı.' });
      }
      res.status(200).json(techLogs);
    } catch (err) {
      console.error(`Oda ${req.params.roomNumber} için sohbet alınırken hata:`, err.message);
      res.status(500).json({ success: false, message: 'Oda sohbeti alınırken hata oluştu.' });
    }
  });
  
  // Yeni bir sohbet mesajı kaydeden endpoint
  app.post('/saveResponsee', async (req, res) => {
    try {
      const { roomNumber, username, message, sender, language } = req.body;
      if (!roomNumber || !username || !message || !sender) {
        return res.status(400).json({ success: false, message: 'Gerekli alanlar eksik.' });
      }
      
      // Aynı oda için daha önce mesaj var mı kontrol ediyoruz.
      const existingMessage = await Tech.findOne({ roomNumber });
      if (!existingMessage) {
        // Bu oda için ilk mesaj, e-posta gönderimi yapılıyor.
        const mailOptions = {
          from: `"${HOTEL_NAME} Tech Admin" <nihatsaydam13131@gmail.com>`,
          to: ADMIN_EMAIL, // Bildirimi almak istenen e-posta adresi
          subject: `Yeni sohbet başlangıcı - Oda: ${roomNumber}`,
          text: `Yeni bir sohbet başladı.
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}
Kullanıcı: ${username}
Mesaj: ${message}`
        };
  
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('E-posta gönderim hatası:', error);
          } else {
            console.log('E-posta gönderildi:', info.response);
          }
        });
      }
      
      // Yeni mesaj kaydı eklenirken status otomatik olarak 'waiting' olacak
      const newTech = new Tech({ roomNumber, username, message, sender, language });
      await newTech.save();
      res.status(200).json({ success: true, message: 'Mesaj kaydedildi!', data: newTech });
    } catch (err) {
      console.error('Mesaj kaydedilirken hata oluştu:', err.message);
      res.status(500).json({ success: false, message: 'Mesaj kaydedilirken hata oluştu.' });
    }
  });
  
  // İsteği kabul eden endpoint: status 'active' olarak güncelleniyor
  app.put('/acceptRequest/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const updatedRequest = await Tech.findByIdAndUpdate(
        id,
        { status: 'active' },
        { new: true }
      );
      if (!updatedRequest) {
        return res.status(404).json({ success: false, message: 'Request not found.' });
      }
      res.status(200).json({ success: true, message: 'Request activated!', data: updatedRequest });
    } catch (err) {
      console.error("Error updating request:", err.message);
      res.status(500).json({ success: false, message: 'Error updating request.' });
    }
  });
  // İsteği kabul eden endpoint: status 'active' olarak güncelleniyor
  app.put('/acceptRequest/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const updatedRequest = await Tech.findByIdAndUpdate(
        id,
        { status: 'active' },
        { new: true }
      );
      if (!updatedRequest) {
        return res.status(404).json({ success: false, message: 'Request not found.' });
      }
      res.status(200).json({ success: true, message: 'Request activated!', data: updatedRequest });
    } catch (err) {
      console.error("Error updating request:", err.message);
      res.status(500).json({ success: false, message: 'Error updating request.' });
    }
  });
  
  // İsteği tamamlanan endpoint: status 'completed' olarak güncelleniyor
  app.put('/completeRequest/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const updatedRequest = await Tech.findByIdAndUpdate(
        id,
        { status: 'completed' },
        { new: true }
      );
      if (!updatedRequest) {
        return res.status(404).json({ success: false, message: 'Request not found.' });
      }
      res.status(200).json({ success: true, message: 'Request completed!', data: updatedRequest });
    } catch (err) {
      console.error("Error updating request:", err.message);
      res.status(500).json({ success: false, message: 'Error updating request.' });
    }
  });
  
  // Opsiyonel: Durum güncellemek için dinamik endpoint
  app.put('/updateRequestStatus/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
      if (!['waiting', 'active', 'completed'].includes(status)) {
        return res.status(400).json({ success: false, message: 'Invalid status value.' });
      }
      const updatedRequest = await Tech.findByIdAndUpdate(
        id,
        { status },
        { new: true }
      );
      if (!updatedRequest) {
        return res.status(404).json({ success: false, message: 'Request not found.' });
      }
      res.status(200).json({ success: true, message: 'Status updated!', data: updatedRequest });
    } catch (err) {
      console.error("Error updating request:", err.message);
      res.status(500).json({ success: false, message: 'Error updating request.' });
    }
  });
  

  const chatSchema = new mongoose.Schema({
    roomNumber: { type: String, required: true },
    username:   { type: String, required: true, default: 'Unknown' },
    message:    { type: String, required: true },
    status:     { type: String, enum: ['waiting','active','completed'], default: 'waiting' },
    sender:     { type: String, enum: ['user','bot'], required: true },
    timestamp:  { type: Date,   default: Date.now }
  }, { collection: 'Concierge' });
  
  const Chat = mongoose.model('Chat', chatSchema);
  
  // E-postalar için transporter


  
  // Sağlık kontrolu

  
  // ====== İstek listesi (filtreli) ======
  app.get('/requests', async (req, res) => {
    try {
      const filter = {};
      if (req.query.status)      filter.status     = req.query.status;
      if (req.query.roomNumber)  filter.roomNumber = req.query.roomNumber;
  
      const data = await Chat.find(filter);
      res.json(data);
    } catch (err) {
      console.error('Error fetching requests:', err);
      res.status(500).json({ success: false, message: 'Error fetching requests.' });
    }
  });
  
  // Tek bir isteği getir
  app.get('/requests/:id', async (req, res) => {
    try {
      const doc = await Chat.findById(req.params.id);
      if (!doc) return res.status(404).json({ success: false, message: 'Request not found.' });
      res.json(doc);
    } catch (err) {
      console.error('Error fetching request:', err);
      res.status(500).json({ success: false, message: 'Error fetching request.' });
    }
  });
  
  // İsteği güncelle (status veya diğer alanlar)
  app.put('/requests/:id/update', async (req, res) => {
    try {
      const updates = { ...req.body, updatedAt: new Date() };
      const updated = await Chat.findByIdAndUpdate(req.params.id, updates, { new: true });
      if (!updated) return res.status(404).json({ success: false, message: 'Request not found.' });
      res.json({ success: true, message: 'Request updated successfully.', data: updated });
    } catch (err) {
      console.error('Error updating request:', err);
      res.status(500).json({ success: false, message: 'Error updating request.' });
    }
  });
  
  // Tek mesajı "active" yap
  app.put('/acceptRequest/:id', async (req, res) => {
    try {
      const updated = await Chat.findByIdAndUpdate(
        req.params.id,
        { status: 'active' },
        { new: true }
      );
      if (!updated) return res.status(404).json({ success: false, message: 'Message not found.' });
      res.json({ success: true, message: 'Request activated.', data: updated });
    } catch (err) {
      console.error('Error activating request:', err);
      res.status(500).json({ success: false, message: 'Error activating request.' });
    }
  });
  
  // Tek mesajı "completed" yap
  app.put('/completeRequest/:id', async (req, res) => {
    try {
      const updated = await Chat.findByIdAndUpdate(
        req.params.id,
        { status: 'completed' },
        { new: true }
      );
      if (!updated) return res.status(404).json({ success: false, message: 'Message not found.' });
      res.json({ success: true, message: 'Request completed.', data: updated });
    } catch (err) {
      console.error('Error completing request:', err);
      res.status(500).json({ success: false, message: 'Error completing request.' });
    }
  });
  
  // Oda bazlı toplu statü güncelleme
  app.put('/updateRequestStatus/:roomNumber', async (req, res) => {
    try {
      const { roomNumber } = req.params;
      const { status }     = req.body;
      const valid          = ['waiting','active','completed'];
  
      if (!valid.includes(status)) {
        return res.status(400).json({ success: false, message: 'Invalid status.' });
      }
  
      await Chat.updateMany({ roomNumber }, { status });
      res.json({ success: true, message: 'All chats in room updated.' });
    } catch (err) {
      console.error('Error updating chat status:', err);
      res.status(500).json({ success: false, message: 'Error updating status.' });
    }
  });
  
  // Oda bazlı sohbet günlüklerini grup halinde getir
  app.get('/getChatLogs', async (req, res) => {
    try {
      const grouped = await Chat.aggregate([
        { $group: { _id: '$roomNumber', messages: { $push: '$$ROOT' } } },
        { $sort:  { _id: 1 } }
      ]);
      res.json(grouped);
    } catch (err) {
      console.error('Error fetching chat logs:', err);
      res.status(500).json({ success: false, message: 'Error fetching chat logs.' });
    }
  });
  
  // Belirli bir odanın sohbetlerini sırayla getir
  app.get('/getChatLogsByRoom/:roomNumber', async (req, res) => {
    try {
      const { roomNumber } = req.params;
      if (!roomNumber) return res.status(400).json({ success: false, message: 'Room number required.' });
  
      const chats = await Chat.find({ roomNumber }).sort({ timestamp: 1 });
      if (!chats.length) return res.status(404).json({ success: false, message: 'No chats for this room.' });
  
      res.json(chats);
    } catch (err) {
      console.error('Error fetching chats by room:', err);
      res.status(500).json({ success: false, message: 'Error fetching chats.' });
    }
  });
  
  // Yeni mesaj kaydet ve mail at
  app.post('/saveResponse', async (req, res) => {
    try {
      const { roomNumber, username, message, sender } = req.body;
      if (!roomNumber || !username || !message || !sender) {
        return res.status(400).json({ success: false, message: 'Missing fields.' });
      }
  
      const chat = new Chat({ roomNumber, username, message, sender });
      await chat.save();
  
      const mailOptions = {
        from: `"${HOTEL_NAME} Concierge" <${process.env.SMTP_USER}>`,
        to: ADMIN_EMAIL,
        subject: `Yeni Mesaj - Oda ${roomNumber}`,
        text: `Yeni mesaj:\n\nOtel: ${HOTEL_NAME}\nOda: ${roomNumber}\nKullanıcı: ${username}\nGönderen: ${sender}\nMesaj: ${message}\nTarih: ${new Date().toLocaleString()}`
      };
      transporter.sendMail(mailOptions, (err, info) => {
        if (err) console.error('Email error:', err);
        else console.log('Email sent:', info.response);
      });
  
      res.json({ success: true, message: 'Message saved and email sent!', chat });
    } catch (err) {
      console.error('Error saving message:', err);
      res.status(500).json({ success: false, message: 'Error saving message.' });
    }
  });


// Bellboy İstek Şeması
const bellboyRequestSchema = new mongoose.Schema({
  roomNumber: { type: String, required: true },
  username: { type: String, required: true },
  clickType: { type: String, required: true },
  details: { type: String },
  selectedTime: { type: Date },
  status: { type: String, default: 'waiting' }  // status eklendi
}, { timestamps: true }); // createdAt otomatik oluşur

const BellboyRequest = mongoose.model('BellboyRequest', bellboyRequestSchema, 'BellboyRequest');

// Bellboy İstek Kaydı ve Mail Bildirimi (POST)
app.post('/saveBellboyRequest', async (req, res) => {
  try {
    const { roomNumber, username, clickType, details, selectedTime } = req.body;

    if (!roomNumber || !clickType) {
      return res.status(400).json({ success: false, message: "Eksik alanlar var: roomNumber, clickType." });
    }

    const newRequest = new BellboyRequest({
      roomNumber,
      username,
      clickType,
      details,
      selectedTime: selectedTime ? new Date(selectedTime) : undefined,
      status: 'waiting'  // default status
    });
    await newRequest.save();

    const mailOptions = {
      from: `"${HOTEL_NAME} Bellboy Notification" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,
      subject: 'Yeni Bellboy İsteği Geldi',
      text: `Yeni Bellboy isteği:
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}
Siparişi veren: ${username}
İstek Türü: ${clickType}
Detaylar: ${details || 'Yok'}
Seçilen Zaman: ${selectedTime ? new Date(selectedTime).toLocaleString() : 'Belirtilmemiş'}

Yönetim panelini kontrol edin.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error('E-posta hatası:', error);
      else console.log('E-posta gönderildi:', info.response);
    });

    await newRequest.save();
    res.status(200).json({ success: true, message: "Bellboy isteği başarıyla oluşturuldu.", bellboyRequest: newRequest });

  } catch (err) {
    console.error("Kayıt hatası:", err);
    res.status(500).json({ success: false, message: "Server hatası oluştu." });
  }
});

// Bellboy İsteklerini Getir (Odaya Göre veya Hepsi)
app.get('/getBellboyRequests', async (req, res) => {
  try {
    const filter = req.query.roomNumber ? { roomNumber: req.query.roomNumber } : {};
    const requests = await BellboyRequest.find(filter).sort({ createdAt: -1 });
    res.status(200).json({ success: true, bellboyRequests: requests });
  } catch (err) {
    console.error('Bellboy istekleri hata:', err.message);
    res.status(500).json({ success: false, message: "Bellboy istekleri alınamadı." });
  }
});

// Bellboy Status Güncelle
app.put('/updateBellboyStatus/:id', async (req, res) => {
  try {
    const updatedRequest = await BellboyRequest.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status },
      { new: true }
    );
    res.json({ success: true, bellboyRequest: updatedRequest });
  } catch (error) {
    console.error("Status güncelleme hatası:", error);
    res.status(500).json({ success: false, message: "Status güncellenemedi." });
  }
});

// *****************
// Laundry Model & Endpoints
// *****************

// Laundry şeması: 'status' alanı eklenmiştir.
const laundrySchema = new mongoose.Schema({
  roomNumber: { type: String, required: true },
  username: { type: String, required: true, default: 'Unknown' },
  items: [{
    name: { type: String, required: true },
    price: { type: String, required: true },
    quantity: { type: Number, required: true },
  }],
  totalPrice: { type: Number, required: true },
  serviceTime: { type: Number, required: true },         // Örneğin, 30, 60, 120, 240
  serviceTimeLabel: { type: String, required: true },      // Örneğin, "In 30 minutes"
  status: { type: String, default: 'waiting' },            // Yeni alan
  createdAt: { type: Date, default: Date.now },
});

// Üçüncü parametre olarak 'Laundry' vererek koleksiyon ismini belirliyoruz.
const Laundry = mongoose.model('Laundry', laundrySchema, 'Laundry');



// Laundry verilerini kaydeden endpoint
app.post('/saveLaundry', async (req, res) => {
  try {
    const { roomNumber, username, items, totalPrice, serviceTime, serviceTimeLabel } = req.body;
    if (!roomNumber || !items || typeof totalPrice === 'undefined' || typeof serviceTime === 'undefined' || !serviceTimeLabel) {
      return res.status(400).json({
        success: false,
        message: 'Gerekli alanlar eksik: roomNumber, items, totalPrice, serviceTime veya serviceTimeLabel.'
      });
    }

    // username gönderilmemişse default değeri kullanıyoruz.
    const newLaundry = new Laundry({ roomNumber, username: username || "Bilinmiyor", items, totalPrice, serviceTime, serviceTimeLabel });
    await newLaundry.save();

    // E-posta gönderimi
    const mailOptions = {
      from: `"${HOTEL_NAME} Laundry Uygulaması" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,  // Bildirim almak istediğiniz e-posta adresi
      subject: 'Yeni Laundry Siparişi Geldi',
      text: `Yeni bir laundry siparişi geldi. 
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}, 
Siparişi veren: ${newLaundry.username}. 
Detaylar için yönetim panelini kontrol edebilirsiniz.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });

    res.status(200).json({
      success: true,
      message: 'Laundry verileri başarıyla kaydedildi!',
      laundry: newLaundry
    });
  } catch (err) {
    console.error('Laundry verileri kaydedilirken hata oluştu:', err.message);
    res.status(500).json({ success: false, message: 'Laundry verileri kaydedilirken hata oluştu.' });
  }
});

// Belirli bir oda numarasına göre Laundry verilerini döndüren endpoint
app.get('/getLaundry/:roomNumber', async (req, res) => {
  try {
    const { roomNumber } = req.params;
    if (!roomNumber) {
      return res.status(400).json({ success: false, message: 'Oda numarası gereklidir.' });
    }
    const laundryData = await Laundry.find({ roomNumber }).sort({ createdAt: -1 });
    if (laundryData.length === 0) {
      return res.status(404).json({ success: false, message: 'Bu odaya ait laundry verisi bulunamadı.' });
    }
    res.status(200).json({ success: true, laundry: laundryData });
  } catch (err) {
    console.error('Laundry verileri alınırken hata oluştu:', err.message);
    res.status(500).json({ success: false, message: 'Laundry verileri alınırken hata oluştu.' });
  }
});
// Sunucu tarafında (server.js)
app.patch('/updateLaundry/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!id || !status) { // Kontroller eklendi
      return res.status(400).json({ success: false, message: 'Eksik ID veya durum.' });
    }
    const updatedLaundry = await Laundry.findByIdAndUpdate(id, { status }, { new: true });
    if (!updatedLaundry) { // Kayıt bulunamazsa kontrol eklendi
      return res.status(404).json({ success: false, message: 'Laundry kaydı bulunamadı.' });
    }
    res.status(200).json({ success: true, laundry: updatedLaundry });
  } catch (err) {
    console.error("Güncelleme hatası:", err.message);
    res.status(500).json({ success: false, message: 'Güncelleme hatası.' });
  }
});


// Laundry siparişlerini oda numarasına göre gruplandıran endpoint
app.get('/getLaundryAll', async (req, res) => {
  const statusFilter = req.query.status;
  let filter = {};
  if (statusFilter && statusFilter !== 'all') {
    filter = { status: statusFilter };
  }
  try {
    const groupedLaundry = await Laundry.aggregate([
      {
        $match: filter
      },
      {
        $sort: { createdAt: -1 } // Önce en yeni siparişler gelsin diye sıralama eklendi
      },
      {
        $group: {
          _id: "$roomNumber",
          orders: { $push: "$$ROOT" }
        }
      },
      {
        $project: {
          roomNumber: "$_id",
          orders: 1,
          _id: 0
        }
      },
       {
        $sort: { roomNumber: 1 } // Oda numarasına göre sırala (isteğe bağlı)
      }
    ]);
    res.status(200).json(groupedLaundry);
  } catch (err) {
    console.error("Laundry siparişleri gruplandırılırken hata oluştu:", err.message);
    res.status(500).json({ success: false, message: "Laundry siparişleri gruplandırılırken hata oluştu." });
  }
});


/// Şikayet Modeli
const ComplainSchema = new mongoose.Schema({
  roomNumber: { type: String, required: true },
  username: { type: String, required: true, default: 'Unknown' },
  message: { type: String, required: true },
  sender: { type: String, enum: ['user', 'bot'], required: true },
  // Yeni eklenen status alanı
  status: { type: String, enum: ['waiting', 'active', 'completed'], default: 'waiting' },
  timestamp: { type: Date, default: Date.now },
});

const Complain = mongoose.model('Complain', ComplainSchema, 'Complain');

// Tüm oda numaralarına göre şikayetleri gruplandıran endpoint
app.get('/getComplain', async (req, res) => {
  try {
    const groupedComplain = await Complain.aggregate([
      {
        $group: {
          _id: "$roomNumber",
          messages: {
            $push: {
              _id: "$_id", // _id bilgisini de ekliyoruz
              message: "$message",
              sender: "$sender",
              status: "$status",
              timestamp: "$timestamp",
              username: "$username"
            }
          },
        },
      },
      {
        $project: {
          roomNumber: "$_id",
          messages: 1,
          _id: 0
        }
      }
    ]);
    
    
    res.status(200).json(groupedComplain);
  } catch (err) {
    console.error('Error fetching complain logs:', err.message);
    res.status(500).json({ success: false, message: 'Error fetching complain logs.' });
  }
});

// Belirli bir oda numarasına ait şikayet kayıtlarını döndüren endpoint
app.get('/getChatLogsByco/:roomNumber', async (req, res) => {
  try {
    const roomNumber = req.params.roomNumber;
    if (!roomNumber) {
      return res.status(400).json({ success: false, message: 'Room number is required.' });
    }
    const complains = await Complain.find({ roomNumber }).sort({ timestamp: 1 });
    if (complains.length === 0) {
      return res.status(404).json({ success: false, message: 'No complains found for this room.' });
    }
    res.status(200).json(complains);
  } catch (err) {
    console.error(`Error fetching complains for room ${req.params.roomNumber}:`, err.message);
    res.status(500).json({ success: false, message: 'Error fetching complains for the room.' });
  }
});

// Yeni bir şikayet mesajı kaydeden ve ardından e-posta bildirimi gönderen endpoint
app.post('/saveComplain', async (req, res) => {
  try {
    const { roomNumber, username, message, sender } = req.body;
    if (!roomNumber || !username || !message || !sender) {
      return res.status(400).json({ success: false, message: 'Missing required fields.' });
    }
    // "status" alanı modelde varsayılan olarak "waiting" olarak ayarlandığı için ayrıca eklemeye gerek yok.
    const newComplain = new Complain({ roomNumber, username, message, sender });
    await newComplain.save();

    // E-posta içeriği
    const mailOptions = {
      from: `"${HOTEL_NAME} Complain Notification" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,
      subject: `Yeni Şikayet - Oda ${roomNumber}`,
      text: `Yeni şikayet geldi:
      
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}
Kullanıcı: ${username}
Mesaj: ${message}
Gönderen: ${sender}
Tarih: ${new Date().toLocaleString()}
Status: waiting
`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });

    res.status(200).json({ success: true, message: 'Message saved and email sent!', complain: newComplain });
  } catch (err) {
    console.error('Error saving message:', err.message);
    res.status(500).json({ success: false, message: 'Error saving message.' });
  }
});

// Şikayet durumunu "waiting" -> "active" olarak güncelleyen endpoint
app.put('/updateStatusToActive/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const complain = await Complain.findById(id);
    if (!complain) {
      return res.status(404).json({ success: false, message: 'Complain not found.' });
    }
    if (complain.status !== 'waiting') {
      return res.status(400).json({ success: false, message: 'Only complaints with status "waiting" can be updated to "active".' });
    }
    complain.status = 'active';
    await complain.save();
    res.status(200).json({ success: true, message: 'Status updated to active.', complain });
  } catch (err) {
    console.error('Error updating status:', err.message);
    res.status(500).json({ success: false, message: 'Error updating status.' });
  }
});

// Şikayet durumunu "active" -> "completed" olarak güncelleyen endpoint
app.put('/updateStatusToCompleted/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const complain = await Complain.findById(id);
    if (!complain) {
      return res.status(404).json({ success: false, message: 'Complain not found.' });
    }
    if (complain.status !== 'active') {
      return res.status(400).json({ success: false, message: 'Only complaints with status "active" can be updated to "completed".' });
    }
    complain.status = 'completed';
    await complain.save();
    res.status(200).json({ success: true, message: 'Status updated to completed.', complain });
  } catch (err) {
    console.error('Error updating status:', err.message);
    res.status(500).json({ success: false, message: 'Error updating status.' });
  }
});

// RoomService şeması
// RoomService şeması
const roomServiceSchema = new mongoose.Schema({
  roomNumber: { type: String, required: true },
  username: { type: String, required: true, default: "Unknown" },
  items: [{
    name: { type: String, required: true },
    price: { type: String, required: true },
    quantity: { type: Number, required: true }
  }],
  totalPrice: { type: Number, required: true },
  serviceTime: { type: Number, required: true },
  serviceTimeLabel: { type: String, required: true },
  
  // Yeni status alanı: waiting, active veya completed
  status: { type: String, enum: ['waiting', 'active', 'completed'], default: 'waiting' },
  
  createdAt: { type: Date, default: Date.now }
});

const RoomService = mongoose.model('RoomService', roomServiceSchema, 'RoomService');

// RoomService verilerini kaydeden endpoint
app.post('/saveRoomservice', async (req, res) => {
  try {
    const { roomNumber, username, items, totalPrice, serviceTime, serviceTimeLabel } = req.body;
    
    // Gerekli alanların kontrolü
    if (!roomNumber || !items || typeof totalPrice === 'undefined' || typeof serviceTime === 'undefined' || !serviceTimeLabel) {
      return res.status(400).json({
        success: false,
        message: "Gerekli alanlar eksik: roomNumber, items, totalPrice, serviceTime veya serviceTimeLabel."
      });
    }
    
    const newRoomService = new RoomService({ roomNumber, username, items, totalPrice, serviceTime, serviceTimeLabel });
    await newRoomService.save();
    const itemsString = items.map(item => `${item.name} (Miktar: ${item.quantity}, Fiyat: ${item.price})`).join(', ');

    // E-posta gönderimi için mailOptions tanımlıyoruz.
    const mailOptions = {
      from: `"${HOTEL_NAME} Room Service" <nihatsaydam13131@gmail.com>`,
      to: [ADMIN_EMAIL],
      // Bildirimi almak istediğiniz e-posta adresi
      subject: 'Yeni Room Service Siparişi Geldi',
      text: `Yeni bir room service siparişi geldi.
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}
Siparişi veren: ${username || 'Bilinmiyor'}
Ürünler: ${itemsString}
Toplam Fiyat: ${totalPrice}₺
Hizmet Süresi: ${serviceTimeLabel} (${serviceTime})
Detaylar için yönetim panelini kontrol edebilirsiniz.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });
    
    res.status(200).json({
      success: true,
      message: "Room service başarıyla kaydedildi!",
      roomService: newRoomService
    });
  } catch (error) {
    console.error("Room service kaydedilirken hata oluştu:", error.message);
    res.status(500).json({
      success: false,
      message: "Room service kaydedilirken hata oluştu."
    });
  }
});

// Tüm RoomService kayıtlarını getiren endpoint
app.get('/getRoomservices', async (req, res) => {
  try {
    // Eğer istek query parametresi ile filtrelenecekse, örn: ?roomNumber=101
    const filter = {};
    if (req.query.roomNumber) {
      filter.roomNumber = req.query.roomNumber;
    }
    const roomServices = await RoomService.find(filter).sort({ createdAt: -1 });
    res.status(200).json({ success: true, roomServices });
  } catch (error) {
    console.error("Room service kayıtları alınırken hata:", error.message);
    res.status(500).json({
      success: false,
      message: "Room service kayıtları alınırken hata oluştu."
    });
  }
});

// Durum güncelleme için endpoint
app.put('/updateRoomServiceStatus/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!['waiting', 'active', 'completed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status value.' });
    }
    const updatedOrder = await RoomService.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );
    if (!updatedOrder) {
      return res.status(404).json({ success: false, message: 'Order not found.' });
    }
    res.status(200).json({ success: true, message: 'Status updated!', data: updatedOrder });
  } catch (err) {
    console.error("Error updating room service status:", err.message);
    res.status(500).json({ success: false, message: 'Error updating room service status.' });
  }
});

const askSchema = new mongoose.Schema({
  roomNumber: { type: String, required: true },
  message: { type: String, required: true },
  sender: { type: String, enum: ['user', 'bot'], required: true },
  status: { type: String, enum: ['waiting', 'Active', 'complate'], default: 'waiting' },
  createdAt: { type: Date, default: Date.now }
});

const Ask = mongoose.model('Ask', askSchema, 'Ask');
app.post('/ask1', async (req, res) => {
  try {
    const { roomNumber, message, sender, status } = req.body;
    const validStatuses = ['waiting', 'Active', 'complate'];
    const msgStatus = (status && validStatuses.includes(status)) ? status : 'waiting';

    const newMessage = new Ask({ roomNumber, message, sender, status: msgStatus });
    const savedMessage = await newMessage.save();
    res.status(201).json({ success: true, data: savedMessage });
  } catch (error) {
    console.error('Mesaj kaydedilirken hata oluştu:', error);
    res.status(500).json({ success: false, error: 'Mesaj kaydedilirken hata oluştu.' });
  }
});
app.get('/ask2/:roomNumber', async (req, res) => {
  try {
    const { roomNumber } = req.params;
    const messages = await Ask.find({ roomNumber }).sort({ createdAt: 1 });
    res.status(200).json({ success: true, data: messages });
  } catch (error) {
    console.error(`Mesajlar çekilirken hata oluştu (Oda ${req.params.roomNumber}):`, error);
    res.status(500).json({ success: false, error: 'Mesajlar çekilirken hata oluştu.' });
  }
});
// GET /getAskRequests endpoint'i
app.get('/getAskRequests', async (req, res) => {
  try {
    // Veritabanından talepleri çek (örneğin, Ask modelin varsa)
    const requests = await Ask.find().sort({ createdAt: -1 }); // En son talepler önce gelsin
    res.status(200).json({ success: true, data: requests });
  } catch (error) {
    console.error('Talepler çekilirken hata oluştu:', error);
    res.status(500).json({ success: false, error: 'Bir hata oluştu' });
  }
});
// Sunucu tarafında status güncelleme endpoint'i (server.js içinde)
app.put('/updateAskStatus/:id/:newStatus', async (req, res) => {
  const { id, newStatus } = req.params;
  const validStatuses = ['waiting', 'Active', 'complate'];
  if (!validStatuses.includes(newStatus)) {
    return res.status(400).json({ success: false, error: 'Geçersiz durum' });
  }
  try {
    const updated = await Ask.findByIdAndUpdate(id, { status: newStatus }, { new: true });
    if (!updated) {
      return res.status(404).json({ success: false, error: 'Kayıt bulunamadı' });
    }
    res.status(200).json({ success: true, data: updated });
  } catch (err) {
    console.error('Status güncellenirken hata:', err);
    res.status(500).json({ success: false, error: 'Güncelleme hatası' });
  }
});

// Sepet (Cart) için bir Mongoose şeması tanımlıyoruz






// Cart (Sepet) modeli şeması
const cartSchema = new mongoose.Schema({
    items: [{
        productName: String,
        quantity: Number,
        price: Number
    }],                         // Sepetteki ürünler listesi (ürün adı, adet, fiyat vb.)
    totalPrice: { type: Number, default: 0 },      // Sepetin toplam tutarı
    createdAt: { type: Date, default: Date.now }   // Oluşturulma tarihi
});
const Cart = mongoose.model('Cart', cartSchema);

// HousekeepingRequest (Oda hizmeti talebi) modeli şeması
const housekeepingRequestSchema = new mongoose.Schema({
    roomNumber: { type: Number, required: true },    // Oda numarası
    requestType: { type: String, required: true },   // Talep türü (ör. "Temizlik", "Havlu", vb.)
    description: { type: String },                   // Talep ile ilgili açıklama
    status: { type: String, default: 'pending' },    // Durum ("pending", "completed" gibi)
    requestedAt: { type: Date, default: Date.now }   // Talep oluşturulma zamanı
});
const HousekeepingRequest = mongoose.model('HousekeepingRequest', housekeepingRequestSchema);




// Tüm sepetleri getir (GET /carts)
app.get('/carts', async (req, res) => {
    try {
        const carts = await Cart.find();
        res.json(carts);
    } catch (error) {
        console.error('Error fetching carts:', error);
        res.status(500).json({ error: 'Sepetler alınamadı' });
    }
});

// Yeni bir sepet oluştur (POST /carts)
app.post('/carts', async (req, res) => {
    try {
        const cartData = req.body;              // İstek gövdesindeki sepet verisi
        const newCart = new Cart(cartData);
        const savedCart = await newCart.save(); // Veritabanına kaydet
        res.status(201).json(savedCart);
    } catch (error) {
        console.error('Error creating cart:', error);
        res.status(500).json({ error: 'Yeni sepet oluşturulamadı' });
    }
});

// Tüm housekeeping taleplerini getir (GET /housekeeping-requests)
app.get('/housekeeping-requests', async (req, res) => {
    try {
        const requests = await HousekeepingRequest.find();
        res.json(requests);
    } catch (error) {
        console.error('Error fetching housekeeping requests:', error);
        res.status(500).json({ error: 'Housekeeping istekleri alınamadı' });
    }
});

// Yeni bir housekeeping talebi oluştur (POST /housekeeping-requests)
app.post('/housekeeping-requests', async (req, res) => {
    try {
        const requestData = req.body;                // İstek gövdesindeki talep verisi
        const newRequest = new HousekeepingRequest(requestData);
        const savedRequest = await newRequest.save(); // Veritabanına kaydet
        res.status(201).json(savedRequest);
    } catch (error) {
        console.error('Error creating housekeeping request:', error);
        res.status(500).json({ error: 'Housekeeping isteği oluşturulamadı' });
    }
});

/* ============================
   SPA Orders (Spa Siparişleri)
============================ */
const spaOrderSchema = new mongoose.Schema({
  username: { type: String, required: true },
  roomNumber: { type: String, required: true },
  spaItems: { type: Array, required: true },
  totalPrice: { type: Number, required: true },
  serviceTime: { type: Number, required: true },         // Hizmet süresi (dakika olarak: 30, 60, 120, 240)
  serviceTimeLabel: { type: String, required: true },    // Hizmet süresi etiketi (örn: "In 30 minutes")
  status: { 
    type: String, 
    enum: ['waiting', 'active', 'completed'], 
    default: 'waiting' 
  },
  timestamp: { type: Date, default: Date.now }
});
const SpaOrder = mongoose.model('SpaOrder', spaOrderSchema, 'spaOrders');

// SPA sipariş kaydetme endpoint'i
app.post('/spa/order', async (req, res) => {
  try {
    const { username, roomNumber, spaItems, totalPrice, serviceTime, serviceTimeLabel } = req.body;
    if (!username || !roomNumber || !spaItems || totalPrice === undefined || !serviceTime || !serviceTimeLabel) {
      return res.status(400).json({ message: 'Eksik alanlar var.' });
    }
    
    const newSpaOrder = new SpaOrder({ 
      username, 
      roomNumber, 
      spaItems, 
      totalPrice,
      serviceTime,
      serviceTimeLabel
    });
    const savedOrder = await newSpaOrder.save();

    // Spa ürünlerini string haline getir
    const itemsString = spaItems
      .map(item => `${item.name} (Miktar: ${item.quantity}, Fiyat: ${item.price})`)
      .join(', ');

    // E-posta içeriğini oluşturma
    const mailOptions = {
      from: `"${HOTEL_NAME} Spa Orders" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,
      subject: 'Yeni Spa Siparişi Geldi',
      text: `Yeni bir spa siparişi alındı.
Otel: ${HOTEL_NAME}
Oda: ${roomNumber}
Kullanıcı: ${username}
Ürünler: ${itemsString}
Toplam Fiyat: ${totalPrice}₺
Seçilen Zaman: ${serviceTimeLabel} (${serviceTime} dakika)
Tarih: ${new Date().toLocaleString()}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });

    res.status(201).json({ message: "Spa order saved", result: savedOrder });
  } catch (error) {
    console.error("Error saving spa order:", error);
    res.status(500).json({ message: "Error saving spa order", error });
  }
});

// SPA siparişlerini getirme endpoint'i
app.get('/spa/orders', async (req, res) => {
  try {
    const { roomNumber, status } = req.query;
    let query = {};
    if (roomNumber) {
      query.roomNumber = roomNumber;
    }
    if (status) {
      query.status = status;
    }
    const orders = await SpaOrder.find(query);
    res.json({ success: true, spaOrders: orders });
  } catch (error) {
    console.error("Spa orders getirme hatası:", error);
    res.status(500).json({ message: "Spa orders getirilemedi", error });
  }
});

// SPA siparişi durum güncelleme endpoint'i
app.put('/spa/order/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (!['waiting', 'active', 'completed'].includes(status)) {
      return res.status(400).json({ message: 'Geçersiz durum değeri' });
    }
    
    const updatedOrder = await SpaOrder.findByIdAndUpdate(
      id, 
      { status }, 
      { new: true }
    );
    
    if (!updatedOrder) {
      return res.status(404).json({ message: 'Sipariş bulunamadı' });
    }
    
    res.json({ message: "Status updated", order: updatedOrder });
  } catch (error) {
    console.error("Spa order status updating error:", error);
    res.status(500).json({ message: "Error updating spa order status", error });
  }
});

/* ============================
   Access Code Feature
============================ */
// Misafir Erişim Kodu Modeli
const accessCodeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  room: { type: String, required: true },
  validUntil: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const AccessCode = mongoose.model('AccessCode', accessCodeSchema, 'GuestAccessCodes');

// API Routes
// 1. Kod Doğrulama
app.post('/api/validate-code', async (req, res) => {
  try {
    const { code } = req.body;
    const accessCode = await AccessCode.findOne({ code });
    
    if (!accessCode || new Date() > new Date(accessCode.validUntil)) {
      console.log(`Geçersiz veya süresi dolmuş kod kullanım denemesi: ${code}`);
      return res.json({ valid: false });
    }
    
    console.log(`Başarılı kod kullanımı: ${code}, Oda: ${accessCode.room}`);
    return res.json({ 
      valid: true, 
      roomNumber: accessCode.room 
    });
  } catch (error) {
    console.error(`Kod doğrulama hatası:`, error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// 2. Yeni Kod Oluşturma
app.post('/api/generate-code', async (req, res) => {
  try {
    const { room, validDays, validHours } = req.body;
    
    if (!room) {
      return res.status(400).json({ success: false, error: 'Oda numarası gerekli' });
    }
    
    // 6 basamaklı rastgele kod oluştur
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Son geçerlilik tarihi hesaplama
    const validUntil = new Date();
    
    // Gün veya saat olarak geçerlilik süresi belirleme
    if (validHours && !isNaN(validHours)) {
      // Saat olarak geçerlilik
      validUntil.setHours(validUntil.getHours() + parseInt(validHours));
    } else {
      // Gün olarak geçerlilik (varsayılan 1 gün)
      const days = (validDays && !isNaN(validDays)) ? parseInt(validDays) : 1;
      validUntil.setDate(validUntil.getDate() + days);
    }
    
    // Yeni kodu veritabanına kaydet
    const newCode = new AccessCode({ 
      code, 
      room, 
      validUntil
    });
    await newCode.save();
    
    console.log(`Yeni misafir kodu oluşturuldu: ${code}, Oda: ${room}, Otel: ${HOTEL_NAME}`);
    
    // E-posta bildirimi
    const mailOptions = {
      from: `"${HOTEL_NAME} Misafir Erişim Kodu" <nihatsaydam13131@gmail.com>`,
      to: ADMIN_EMAIL,
      subject: `Yeni Misafir Erişim Kodu Oluşturuldu - ${HOTEL_NAME}`,
      text: `Yeni bir misafir erişim kodu oluşturuldu:
      
Otel: ${HOTEL_NAME}
Oda: ${room}
Kod: ${code}
Oluşturulma: ${new Date().toLocaleString()}
Geçerlilik Sonu: ${validUntil.toLocaleString()}
`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('E-posta gönderim hatası:', error);
      } else {
        console.log('E-posta gönderildi:', info.response);
      }
    });
    
    res.json({ 
      success: true,
      code, 
      room, 
      createdAt: new Date(),
      validUntil,
      expiresIn: validHours 
        ? `${validHours} saat` 
        : `${validDays || 1} gün`,
      hotel: HOTEL_NAME 
    });
  } catch (error) {
    console.error(`Kod oluşturma hatası:`, error);
    res.status(500).json({ error: 'Kod oluşturulurken hata oluştu' });
  }
});

// 3. Tüm Aktif Kodları Listele
app.get('/api/list-codes', async (req, res) => {
  try {
    const now = new Date();
    const codes = await AccessCode.find({ 
      validUntil: { $gt: now }
    }).sort({ createdAt: -1 });
    
    console.log(`${codes.length} aktif misafir kodu listelendi (${HOTEL_NAME})`);
    res.json(codes);
  } catch (error) {
    console.error(`Kod listeleme hatası:`, error);
    res.status(500).json({ error: 'Kodlar listelenirken hata oluştu' });
  }
});

// 4. Kod Silme
app.delete('/api/delete-code/:code', async (req, res) => {
  try {
    const result = await AccessCode.deleteOne({ 
      code: req.params.code
    });
    
    if (result.deletedCount > 0) {
      console.log(`Misafir kodu silindi: ${req.params.code}`);
      res.json({ success: true });
    } else {
      console.log(`Silinecek kod bulunamadı: ${req.params.code}`);
      res.status(404).json({ success: false, error: 'Kod bulunamadı' });
    }
  } catch (error) {
    console.error(`Kod silme hatası:`, error);
    res.status(500).json({ error: 'Kod silinirken hata oluştu' });
  }
});

/* ============================
   User Management (Kullanıcı Yönetimi)
============================ */
// User (Kullanıcı) modeli - Artık yukarıda tanımlanıyor
// (İlk tanım satır ~23'te olduğu için buradan kaldırıyoruz)

// ActivityLog (İşlem Günlüğü) modeli - Artık yukarıda tanımlanıyor

// İlk admin kullanıcısını oluştur - Yukarıda tanımlandı ve çağrıldı

// Ana sayfa endpoint'i (Opsiyonel)
app.get('/', (req, res) => {
  res.send('Welcome to Keepsty Backend API!');
});

// Uygulama başlangıcında admin kullanıcısı oluştur
// Yukarıda MongoDB bağlantısı sonrasında çağrıldığı için burada çağrılmamalı
// createInitialAdmin();
 
/* ============================
   User Management API Endpoints
============================ */

// Kullanıcı girişi
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Kullanıcıyı kontrol et
    const user = await User.findOne({ username, hotelName: HOTEL_NAME });
    if (!user) {
      return res.status(400).json({ message: 'Kullanıcı adı veya şifre yanlış' });
    }
    
    // Şifreyi kontrol et
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Kullanıcı adı veya şifre yanlış' });
    }
    
    // Session bilgilerini ayarla
    req.session.user = {
      id: user._id,
      username: user.username,
      permissions: user.permissions,
      hotelName: user.hotelName
    };
    
    // Giriş logunu kaydet
    logActivity('login', user.username);
    
    // Kullanıcı bilgilerini gönder (şifre olmadan)
    const userResponse = {
      username: user.username,
      permissions: user.permissions,
      hotelName: user.hotelName
    };
    
    res.json({ message: 'Giriş başarılı', user: userResponse });
    
  } catch (error) {
    console.error('Giriş hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Kullanıcı çıkışı
app.post('/api/logout', (req, res) => {
  if (req.session.user) {
    const username = req.session.user.username;
    logActivity('logout', username);
    
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: 'Çıkış yapılamadı' });
      }
      res.json({ message: 'Çıkış başarılı' });
    });
  } else {
    res.status(400).json({ message: 'Oturum bulunamadı' });
  }
});

// Kullanıcı kontrolü (session kontrol)
app.get('/api/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ 
      isAuthenticated: true, 
      user: req.session.user 
    });
  } else {
    res.json({ isAuthenticated: false });
  }
});

// Yeni kullanıcı oluşturma
app.post('/api/users', async (req, res) => {
  try {
    // Session kontrolü
    if (!req.session.user || !req.session.user.permissions.admin) {
      return res.status(403).json({ message: 'Bu işlem için yetkiniz yok' });
    }
    
    const { username, password, permissions } = req.body;
    
    // Kullanıcı adının bu otel için benzersiz olup olmadığını kontrol et
    const existingUser = await User.findOne({ 
      username, 
      hotelName: HOTEL_NAME 
    });
    
    if (existingUser) {
      return res.status(400).json({ message: 'Bu kullanıcı adı zaten kullanılıyor' });
    }
    
    // Yeni kullanıcıyı oluştur
    const newUser = new User({
      username,
      password,
      permissions,
      createdBy: req.session.user.username,
      hotelName: HOTEL_NAME
    });
    
    await newUser.save();
    
    // İşlemi logla
    logActivity('create_user', req.session.user.username, { created_username: username });
    
    res.status(201).json({ 
      message: 'Kullanıcı başarıyla oluşturuldu',
      user: {
        username: newUser.username,
        permissions: newUser.permissions,
        hotelName: newUser.hotelName
      }
    });
    
  } catch (error) {
    console.error('Kullanıcı oluşturma hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Kullanıcıları listeleme (sadece mevcut oteldeki)
app.get('/api/users', async (req, res) => {
  try {
    // Session kontrolü
    if (!req.session.user || !req.session.user.permissions.admin) {
      return res.status(403).json({ message: 'Bu işlem için yetkiniz yok' });
    }
    
    const users = await User.find({ hotelName: HOTEL_NAME }, '-password');
    res.json(users);
    
  } catch (error) {
    console.error('Kullanıcı listeleme hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Kullanıcı silme
app.delete('/api/users/:username', async (req, res) => {
  try {
    // Session kontrolü
    if (!req.session.user || !req.session.user.permissions.admin) {
      return res.status(403).json({ message: 'Bu işlem için yetkiniz yok' });
    }
    
    const { username } = req.params;
    
    // Admin kullanıcısını silme koruması
    if (username === 'admin') {
      return res.status(400).json({ message: 'Admin kullanıcısı silinemez' });
    }
    
    // Kendi hesabını silmesini engelle
    if (username === req.session.user.username) {
      return res.status(400).json({ message: 'Kendi hesabınızı silemezsiniz' });
    }
    
    const result = await User.deleteOne({ 
      username, 
      hotelName: HOTEL_NAME 
    });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
    }
    
    // İşlemi logla
    logActivity('delete_user', req.session.user.username, { deleted_username: username });
    
    res.json({ message: 'Kullanıcı başarıyla silindi' });
    
  } catch (error) {
    console.error('Kullanıcı silme hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Kullanıcı güncelleme
app.put('/api/users/:username', async (req, res) => {
  try {
    // Session kontrolü
    if (!req.session.user || !req.session.user.permissions.admin) {
      return res.status(403).json({ message: 'Bu işlem için yetkiniz yok' });
    }
    
    const { username } = req.params;
    const { permissions, password } = req.body;
    
    const user = await User.findOne({ username, hotelName: HOTEL_NAME });
    
    if (!user) {
      return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
    }
    
    // Admin kullanıcısına özel koruma
    if (username === 'admin' && req.session.user.username !== 'admin') {
      return res.status(400).json({ message: 'Admin kullanıcısı sadece kendisi tarafından düzenlenebilir' });
    }
    
    // Yetkileri güncelle
    if (permissions) {
      user.permissions = permissions;
    }
    
    // Şifreyi güncelle (şifre değiştiriliyorsa)
    if (password) {
      user.password = password;
    }
    
    await user.save();
    
    // İşlemi logla
    logActivity('update_user', req.session.user.username, { updated_username: username });
    
    res.json({ 
      message: 'Kullanıcı başarıyla güncellendi',
      user: {
        username: user.username,
        permissions: user.permissions,
        hotelName: user.hotelName
      }
    });
    
  } catch (error) {
    console.error('Kullanıcı güncelleme hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// İşlem günlüğünü listeleme
app.get('/api/activity-logs', async (req, res) => {
  try {
    // Session kontrolü
    if (!req.session.user || !req.session.user.permissions.admin) {
      return res.status(403).json({ message: 'Bu işlem için yetkiniz yok' });
    }
    
    // Sadece mevcut otelin loglarını getir
    const logs = await ActivityLog.find({ 
      hotelName: HOTEL_NAME 
    }).sort({ timestamp: -1 }).limit(100);
    
    res.json(logs);
    
  } catch (error) {
    console.error('Log listeleme hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// İşlem logunu kaydet (diğer servisler için)
app.post('/api/log-activity', async (req, res) => {
  try {
    // Session kontrolü
    if (!req.session.user) {
      return res.status(403).json({ message: 'Oturum açmanız gerekiyor' });
    }
    
    const { action, details } = req.body;
    
    logActivity(action, req.session.user.username, details);
    
    res.json({ message: 'İşlem kaydedildi' });
    
  } catch (error) {
    console.error('Log kaydetme hatası:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Sağlık kontrolu
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    message: `${HOTEL_NAME} backend is running`,
    dbName: DB_NAME
  });
});

// Sunucuyu başlat
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
   