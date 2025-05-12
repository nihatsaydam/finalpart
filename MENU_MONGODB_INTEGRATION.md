# Room Service Menu - MongoDB Integration

This document explains how the room service menu data is now integrated with MongoDB Atlas.

## Overview

Instead of using static JSON files for menu data, we've implemented a MongoDB-based approach that:

1. Stores menu data in a MongoDB collection called `menu`
2. Provides API endpoints to fetch menu data by language
3. Handles fallback to English if a requested language is not available
4. Supports multiple languages (en, tr, fr, ar)

## MongoDB Schema

The menu data follows this schema structure:

```javascript
{
  language: String,  // 'en', 'tr', 'fr', 'ar' 
  menu: [
    {
      key: String,   // Category identifier
      name: String,  // Displayed category name
      image: String, // Category image path
      items: [
        {
          name: String,        // Item name
          price: String,       // Item price (e.g. "400 TL")
          description: String, // Item description
          image: String        // Item image path
        }
      ]
    }
  ]
}
```

## API Endpoints

### 1. Get Menu Data

**Endpoint:** `GET /api/menu/:language`

Fetches menu data for the specified language code.

**Path Parameters:**
- `language`: Language code (en, tr, fr, ar)

**Response:**
- Success (200): Menu data object
- Error (400): Invalid language code
- Error (404): Menu not found for language (and no fallback available)
- Error (500): Server error

### 2. Create/Update Menu Data

**Endpoint:** `POST /api/menu`

Creates or updates menu data for a specific language.

**Request Body:**
```json
{
  "language": "en",
  "menu": [
    {
      "key": "Category1",
      "name": "Category Name",
      "image": "path/to/image.png",
      "items": [
        {
          "name": "Item Name",
          "price": "50 TL",
          "description": "Item description",
          "image": "path/to/item-image.png"
        }
      ]
    }
  ]
}
```

**Response:**
- Success (200): Created/updated menu data
- Error (400): Invalid request body
- Error (500): Server error

## How to Populate Sample Menu Data

We've included scripts to help populate the database with sample menu data:

1. For English menu only:
   ```
   npm run populate-menu-en
   ```

2. For all supported languages (en, tr, fr, ar):
   ```
   npm run populate-all-menus
   ```

## Client-Side Integration

The client-side code has been updated to fetch menu data from the MongoDB API instead of static JSON files:

```javascript
// Updated loadMenuData function in client code
async function loadMenuData(language) {
  try {
    const apiUrl = `https://your-server-url.com/api/menu/${language}`;
    const response = await fetch(apiUrl);
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    const data = await response.json();
    menuData = data;
    
    // Display categories and menu items
    displayCategories(data.menu || []);
    
    // Update search placeholder
    updateSearchPlaceholder();
  } catch (error) {
    // Error handling and fallback logic
    console.error("Error loading menu data:", error);
    
    // Try fallback to English if current language is not English
    if (language !== 'en') {
      currentLanguage = 'en';
      loadMenuData('en');
    } else {
      showErrorMessage("Failed to load menu data. Please check your connection and try again.");
    }
  }
}
```

## Fallback Mechanism

If the requested language is not available, the system will try to fall back to English.
This happens both on the server side and on the client side for maximum reliability.

## Benefits of This Approach

1. **Centralized Data Management**: All menu data is stored in one location.
2. **Language Flexibility**: Easy to add or update languages without changing front-end code.
3. **Dynamic Updates**: Menu items can be updated without redeploying the application.
4. **Consistency**: The same menu data is available to all clients. 