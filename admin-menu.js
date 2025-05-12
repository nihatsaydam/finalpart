// admin-menu.js - Menü yönetim panel sunucusu

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

// Admin panel sunucusu
const adminApp = express();
const PORT = process.env.ADMIN_PORT || 8081;

// Otel adı ve veritabanı adını environment variable'lardan al (varsayılan değerler ile)
const HOTEL_NAME = process.env.HOTEL_NAME || 'Default Hotel';
const DB_NAME = process.env.DB_NAME || 'GreenP';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'nihat.saydam@icloud.com';

console.log(`Starting admin panel for hotel: ${HOTEL_NAME}`);
console.log(`Using database: ${DB_NAME}`);

// MongoDB Atlas bağlantısı
mongoose
  .connect(
    `mongodb+srv://nihatsaydam13131:nihat1234@keepsty.hrq40.mongodb.net/${DB_NAME}?retryWrites=true&w=majority&appName=${DB_NAME}`
  )
  .then(() => console.log(`Admin panel connected to MongoDB Atlas ${DB_NAME} Database!`))
  .catch((err) => console.error('Error connecting to MongoDB Atlas:', err));

// Middleware
adminApp.use(cors());
adminApp.use(express.json());
adminApp.use(express.static(path.join(__dirname, 'admin-panel')));

// Menu Schema definitions - same as in server.js
const menuItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: String, required: true },
  description: { type: String },
  image: { type: String }
});

const menuCategorySchema = new mongoose.Schema({
  key: { type: String, required: true },
  name: { type: String, required: true },
  image: { type: String },
  items: [menuItemSchema]
});

const menuSchema = new mongoose.Schema({
  language: { type: String, required: true }, // 'en', 'tr', 'fr', 'ar'
  menu: [menuCategorySchema]
});

const Menu = mongoose.model('Menu', menuSchema, 'menu');

// API Routes for Admin Panel

// Get hotel info for admin panel
adminApp.get('/api/hotel-info', (req, res) => {
  res.json({
    hotelName: HOTEL_NAME,
    dbName: DB_NAME
  });
});

// Get all menu languages for this hotel
adminApp.get('/api/admin/menu-languages', async (req, res) => {
  try {
    // Retrieve all available language versions for this hotel's menu
    const menus = await Menu.find({}, { language: 1 });
    const languages = menus.map(menu => menu.language);
    res.status(200).json({ success: true, languages });
  } catch (error) {
    console.error("Error fetching menu languages:", error.message);
    res.status(500).json({ success: false, message: "Error fetching menu languages" });
  }
});

// Get menu for a specific language
adminApp.get('/api/admin/menu/:language', async (req, res) => {
  try {
    const { language } = req.params;
    const menuData = await Menu.findOne({ language });
    res.status(200).json({ success: true, menu: menuData || { language, menu: [] } });
  } catch (error) {
    console.error("Error fetching menu:", error.message);
    res.status(500).json({ success: false, message: "Error fetching menu" });
  }
});

// Create or update menu for a language
adminApp.post('/api/admin/menu/:language', async (req, res) => {
  try {
    const { language } = req.params;
    const { menu } = req.body;
    
    if (!menu || !Array.isArray(menu)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid menu data format. Menu must be an array of categories."
      });
    }
    
    // Validate menu structure
    for (const category of menu) {
      if (!category.key || !category.name || !category.items || !Array.isArray(category.items)) {
        return res.status(400).json({
          success: false,
          message: "Invalid category format. Each category must have key, name, and items array."
        });
      }
      
      for (const item of category.items) {
        if (!item.name || !item.price) {
          return res.status(400).json({
            success: false,
            message: "Invalid item format. Each item must have at least name and price."
          });
        }
      }
    }
    
    // Check if menu for this language already exists
    const existingMenu = await Menu.findOne({ language });
    
    if (existingMenu) {
      // Update existing menu
      existingMenu.menu = menu;
      await existingMenu.save();
      res.status(200).json({ 
        success: true, 
        message: `Menu for ${language} updated successfully`,
        menu: existingMenu
      });
    } else {
      // Create new menu
      const newMenu = new Menu({ language, menu });
      await newMenu.save();
      res.status(201).json({ 
        success: true, 
        message: `Menu for ${language} created successfully`,
        menu: newMenu
      });
    }
  } catch (error) {
    console.error("Error saving menu:", error.message);
    res.status(500).json({ success: false, message: "Error saving menu" });
  }
});

// Delete menu for a language
adminApp.delete('/api/admin/menu/:language', async (req, res) => {
  try {
    const { language } = req.params;
    const result = await Menu.deleteOne({ language });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: `No menu found for language: ${language}` });
    }
    
    res.status(200).json({ success: true, message: `Menu for ${language} deleted successfully` });
  } catch (error) {
    console.error("Error deleting menu:", error.message);
    res.status(500).json({ success: false, message: "Error deleting menu" });
  }
});

// Start the admin panel server
adminApp.listen(PORT, () => {
  console.log(`Admin panel running on port ${PORT} for ${HOTEL_NAME}`);
}); 