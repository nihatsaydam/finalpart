// Script to populate MongoDB with menu data for all languages

const mongoose = require('mongoose');

// MongoDB connection string
const MONGO_URI = 'mongodb+srv://nihatsaydam13131:nihat1234@keepsty.hrq40.mongodb.net/GreenP?retryWrites=true&w=majority&appName=GreenP';

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

// Base menu data structure (English version)
const baseMenuData = {
  menu: [
    {
      key: "Kebabs",
      name: "Kebabs",
      image: "assets/yemek/kebab.png",
      items: [
        {
          name: "Urfa Kebap Acısız",
          price: "400 TL",  
          image: "https://i.ibb.co/s965R2JK/Urfakebap.png",
          description: "Mild ground lamb kebab, grilled and served without chili."
        },
        {
          name: "Adana Kebap Acılı",
          price: "400 TL",
          image: "https://i.ibb.co/NXTNSt0/Adanakebap.png",
          description: "Spicy ground lamb kebab, grilled with traditional chili and spices."
        }
      ]
    },
    {
      key: "Starters",
      name: "Starters & Appetizers",
      image: "assets/icons/appetizers.png",
      items: [
        {
          name: "Ezo Gelin Çorba",
          price: "128 TL",  
          image: "https://i.ibb.co/6jqZxrT/ezogelinçorba.png",
          description: "Traditional Turkish red lentil soup with bulgur, rice, tomato paste, and spices."
        }
      ]
    },
    {
      key: "Beverages",
      name: "Beverages",
      image: "assets/icons/drinks.png",
      items: [
        {
          name: "Su",
          price: "50 TL",
          description: "Bottled water."
        }
      ]
    }
  ]
};

// Language translations for category names and item descriptions
const translations = {
  en: {
    categories: {
      "Kebabs": "Kebabs",
      "Starters": "Starters & Appetizers",
      "Beverages": "Beverages"
    },
    descriptions: {
      "Urfa Kebap Acısız": "Mild ground lamb kebab, grilled and served without chili.",
      "Adana Kebap Acılı": "Spicy ground lamb kebab, grilled with traditional chili and spices.",
      "Ezo Gelin Çorba": "Traditional Turkish red lentil soup with bulgur, rice, tomato paste, and spices.",
      "Su": "Bottled water."
    }
  },
  tr: {
    categories: {
      "Kebabs": "Kebaplar",
      "Starters": "Başlangıçlar & Mezeler",
      "Beverages": "İçecekler"
    },
    descriptions: {
      "Urfa Kebap Acısız": "Acısız kuzu kıyma kebabı, ızgara yapılmış ve acı bibersiz servis edilir.",
      "Adana Kebap Acılı": "Acılı kuzu kıyma kebabı, geleneksel acı biber ve baharatlarla ızgara yapılır.",
      "Ezo Gelin Çorba": "Geleneksel Türk kırmızı mercimek çorbası, bulgur, pirinç, domates salçası ve baharatlarla.",
      "Su": "Şişe su."
    }
  },
  fr: {
    categories: {
      "Kebabs": "Kebabs",
      "Starters": "Entrées & Hors d'œuvres",
      "Beverages": "Boissons"
    },
    descriptions: {
      "Urfa Kebap Acısız": "Kebab d'agneau haché doux, grillé et servi sans piment.",
      "Adana Kebap Acılı": "Kebab d'agneau haché épicé, grillé avec du piment et des épices traditionnelles.",
      "Ezo Gelin Çorba": "Soupe traditionnelle turque aux lentilles rouges avec du boulgour, du riz, de la pâte de tomate et des épices.",
      "Su": "Eau en bouteille."
    }
  },
  ar: {
    categories: {
      "Kebabs": "كباب",
      "Starters": "المقبلات",
      "Beverages": "المشروبات"
    },
    descriptions: {
      "Urfa Kebap Acısız": "كباب لحم الضأن المفروم الخفيف، مشوي ويقدم بدون فلفل حار.",
      "Adana Kebap Acılı": "كباب لحم الضأن المفروم الحار، مشوي مع الفلفل الحار والتوابل التقليدية.",
      "Ezo Gelin Çorba": "حساء العدس الأحمر التركي التقليدي مع البرغل والأرز ومعجون الطماطم والتوابل.",
      "Su": "ماء معبأ."
    }
  }
};

// Function to create menu data for a specific language
function createLanguageMenu(language) {
  const menuData = JSON.parse(JSON.stringify(baseMenuData)); // Deep clone
  
  // Apply translations to category names and item descriptions
  menuData.menu.forEach(category => {
    // Translate category name if available
    if (translations[language].categories[category.key]) {
      category.name = translations[language].categories[category.key];
    }
    
    // Translate item descriptions
    category.items.forEach(item => {
      if (translations[language].descriptions[item.name]) {
        item.description = translations[language].descriptions[item.name];
      }
    });
  });
  
  return {
    language: language,
    menu: menuData.menu
  };
}

async function populateMenuDataForAllLanguages() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB Atlas!');

    // Create model
    const Menu = mongoose.model('Menu', menuSchema, 'menu');
    
    // Languages to populate
    const languages = ['en', 'tr', 'fr', 'ar'];
    
    // Populate each language
    for (const language of languages) {
      console.log(`Processing menu data for ${language}...`);
      
      const menuData = createLanguageMenu(language);
      
      // Check if menu data already exists for this language
      const existingMenu = await Menu.findOne({ language });
      
      if (existingMenu) {
        console.log(`Menu data for ${language} already exists. Updating...`);
        await Menu.findOneAndUpdate({ language }, menuData);
        console.log(`Menu data for ${language} updated successfully!`);
      } else {
        console.log(`Creating new menu data for ${language}...`);
        const newMenu = new Menu(menuData);
        await newMenu.save();
        console.log(`Menu data for ${language} created successfully!`);
      }
    }
    
    // Disconnect
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB Atlas');
    
  } catch (error) {
    console.error('Error populating menu data:', error);
  }
}

// Run the population function
populateMenuDataForAllLanguages(); 