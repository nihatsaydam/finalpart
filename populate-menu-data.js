// Script to populate MongoDB with menu data

const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// MongoDB connection string - replace with your actual connection string if different
const MONGO_URI = 'mongodb+srv://nihatsaydam13131:nihat1234@keepsty.hrq40.mongodb.net/GreenP?retryWrites=true&w=majority&appName=GreenP';

// Example menu data for English language
const exampleMenuData = {
  "language": "en",
  "menu": [
    {
      "key": "Kebabs",
      "name": "Kebabs",
      "image": "assets/yemek/kebab.png",
      "items": [
        {
          "name": "Urfa Kebap Acısız",
          "price": "400 TL",  
          "image": "https://i.ibb.co/s965R2JK/Urfakebap.png",
          "description": "Mild ground lamb kebab, grilled and served without chili."
        },
        {
          "name": "Adana Kebap Acılı",
          "price": "400 TL",
          "image": "https://i.ibb.co/NXTNSt0/Adanakebap.png",
          "description": "Spicy ground lamb kebab, grilled with traditional chili and spices."
        },
        {
          "name": "Patlıcanlı Kebap",
          "price": "720 TL",
          "image": "https://i.ibb.co/V09jj5JV/Patlicanlikebap.png",
          "description": "Chargrilled kebab layered with eggplant slices."
        },
        {
          "name": "Karışık Kebap (Tek Kişilik)",
          "price": "960 TL",
          "image": "https://i.ibb.co/QFYL1z8K/Karisikkebap.png",
          "description": "Mixed grill platter including various kebabs, served for one person."
        },
        {
          "name": "Domatesli Kebap",
          "price": "640 TL",
          "image": "https://i.ibb.co/dw9zZxfK/Domateslikebap.png",
          "description": "Grilled kebab served with roasted tomatoes and a tomato-based sauce."
        }
      ]
    },
    {
      "key": "Starters & Appetizers",
      "name": "Starters & Appetizers",
      "image": "assets/icons/appetizers.png",
      "items": [
        {
          "name": "Ezo Gelin Çorba",
          "price": "128 TL",  
          "image": "https://i.ibb.co/6jqZxrT/ezogelinçorba.png",
          "description": "Traditional Turkish red lentil soup with bulgur, rice, tomato paste, and spices."
        },
        {
          "name": "Çoban Salatası",
          "price": "128 TL",
          "image": "https://i.ibb.co/ynFfZptG/Çobansalata.png",
          "description": "Shepherd's salad with chopped tomatoes, cucumbers, onions, parsley, and olive oil-lemon dressing."
        }
      ]
    },
    {
      "key": "Beverages",
      "name": "Beverages",
      "image": "assets/icons/drinks.png",
      "items": [
        {
          "name": "Su",
          "price": "50 TL",
          "description": "Bottled water."
        },
        {
          "name": "Yayık Ayran",
          "price": "50 TL",
          "description": "Traditional Turkish buttermilk, tangy and foamy, served cold."
        }
      ]
    }
  ]
};

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

async function populateMenuData() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB Atlas!');

    // Create model
    const Menu = mongoose.model('Menu', menuSchema, 'menu');
    
    // Check if menu data already exists for English
    const existingMenu = await Menu.findOne({ language: 'en' });
    
    if (existingMenu) {
      console.log('Menu data for English already exists. Updating...');
      await Menu.findOneAndUpdate({ language: 'en' }, exampleMenuData);
      console.log('Menu data updated successfully!');
    } else {
      console.log('Creating new menu data for English...');
      const newMenu = new Menu(exampleMenuData);
      await newMenu.save();
      console.log('Menu data created successfully!');
    }
    
    // Disconnect
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB Atlas');
    
  } catch (error) {
    console.error('Error populating menu data:', error);
  }
}

// Run the population function
populateMenuData(); 