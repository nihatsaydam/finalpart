// Admin Panel için JavaScript

// Global değişkenler
let currentLanguage = 'en';
let currentMenu = null;
let hotelInfo = null;

// DOM yüklendiğinde çalıştır
document.addEventListener('DOMContentLoaded', () => {
  // Otel bilgilerini al
  fetchHotelInfo();
  
  // Event listener'ları ayarla
  setupEventListeners();
});

// Otel bilgilerini getir
async function fetchHotelInfo() {
  try {
    const response = await fetch('/api/hotel-info');
    if (!response.ok) {
      throw new Error('Otel bilgileri alınamadı');
    }
    
    hotelInfo = await response.json();
    
    // Otel bilgilerini UI'da güncelle
    document.getElementById('hotel-name').textContent = hotelInfo.hotelName + ' - Menü Yönetimi';
    document.getElementById('db-name').textContent = 'Veritabanı: ' + hotelInfo.dbName;
    
    // Varsayılan dildeki menüyü yükle
    loadMenu(currentLanguage);
  } catch (error) {
    showAlert('Otel bilgileri alınamadı: ' + error.message, 'danger');
  }
}

// Event listener'ları ayarla
function setupEventListeners() {
  // Dil değiştirme butonu
  document.getElementById('load-language-btn').addEventListener('click', () => {
    const selectedLanguage = document.getElementById('language-select').value;
    loadMenu(selectedLanguage);
  });
  
  // Yeni menü oluşturma
  document.getElementById('create-menu-btn').addEventListener('click', createNewMenu);
  
  // Kategori ekleme
  document.getElementById('add-category-btn').addEventListener('click', addCategory);
  
  // Menü kaydetme
  document.getElementById('save-menu-btn').addEventListener('click', saveMenu);
  
  // Menü silme
  document.getElementById('delete-menu-btn').addEventListener('click', deleteMenu);
}

// Belirli bir dildeki menüyü yükle
async function loadMenu(language) {
  try {
    currentLanguage = language;
    
    // UI'da dil seçimini güncelle
    document.getElementById('language-select').value = language;
    
    const response = await fetch(`/api/admin/menu/${language}`);
    if (!response.ok) {
      throw new Error(`Menü verileri alınamadı: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (data.success && data.menu) {
      currentMenu = data.menu;
      
      // Menü verilerini göster
      displayMenu(currentMenu);
    } else {
      // Menü bulunamadı
      showAlert(`${language} dilinde menü bulunamadı. Yeni bir menü oluşturabilirsiniz.`, 'info');
      document.getElementById('menu-editor').classList.add('d-none');
      document.getElementById('info-alert').classList.remove('d-none');
    }
  } catch (error) {
    showAlert('Menü yüklenirken hata oluştu: ' + error.message, 'danger');
  }
}

// Menüyü ekranda göster
function displayMenu(menuData) {
  document.getElementById('info-alert').classList.add('d-none');
  document.getElementById('menu-editor').classList.remove('d-none');
  
  document.getElementById('editor-title').textContent = `${currentLanguage.toUpperCase()} Dilindeki Menüyü Düzenle`;
  
  // Kategori konteynerini temizle
  const categoriesContainer = document.getElementById('categories-container');
  categoriesContainer.innerHTML = '';
  
  // Menü verileri yoksa veya menü boşsa
  if (!menuData.menu || menuData.menu.length === 0) {
    // Boş bir kategori oluştur
    addCategory();
    return;
  }
  
  // Her kategori için UI oluştur
  menuData.menu.forEach(category => {
    const categoryElement = createCategoryElement(category);
    categoriesContainer.appendChild(categoryElement);
  });
}

// Yeni kategori elementi oluştur
function createCategoryElement(category = null) {
  const template = document.getElementById('category-template');
  const clone = document.importNode(template.content, true);
  
  const categoryCard = clone.querySelector('.category-card');
  
  // Eğer kategori verileri varsa, doldur
  if (category) {
    categoryCard.querySelector('.category-name').value = category.name || '';
    categoryCard.querySelector('.category-key').value = category.key || '';
    categoryCard.querySelector('.category-image').value = category.image || '';
    
    // Kategoriye ait ürünleri ekle
    const itemsContainer = categoryCard.querySelector('.items-container');
    
    if (category.items && category.items.length > 0) {
      category.items.forEach(item => {
        const itemElement = createItemElement(item);
        itemsContainer.appendChild(itemElement);
      });
    }
  }
  
  // Kategori silme butonu
  categoryCard.querySelector('.remove-category-btn').addEventListener('click', function() {
    if (confirm('Bu kategoriyi silmek istediğinizden emin misiniz?')) {
      categoryCard.remove();
    }
  });
  
  // Ürün ekleme butonu
  categoryCard.querySelector('.add-item-btn').addEventListener('click', function() {
    const itemsContainer = this.previousElementSibling;
    const itemElement = createItemElement();
    itemsContainer.appendChild(itemElement);
  });
  
  return categoryCard;
}

// Yeni ürün elementi oluştur
function createItemElement(item = null) {
  const template = document.getElementById('item-template');
  const clone = document.importNode(template.content, true);
  
  const itemCard = clone.querySelector('.item-card');
  
  // Eğer ürün verileri varsa, doldur
  if (item) {
    itemCard.querySelector('.item-name').value = item.name || '';
    itemCard.querySelector('.item-description').value = item.description || '';
    itemCard.querySelector('.item-price').value = item.price || '';
    itemCard.querySelector('.item-image').value = item.image || '';
  }
  
  // Ürün silme butonu
  itemCard.querySelector('.remove-item-btn').addEventListener('click', function() {
    if (confirm('Bu ürünü silmek istediğinizden emin misiniz?')) {
      itemCard.remove();
    }
  });
  
  return itemCard;
}

// Yeni kategori ekle
function addCategory() {
  const categoriesContainer = document.getElementById('categories-container');
  const categoryElement = createCategoryElement();
  
  // Editör alanını göster
  document.getElementById('info-alert').classList.add('d-none');
  document.getElementById('menu-editor').classList.remove('d-none');
  
  // Kategoriyi ekle
  categoriesContainer.appendChild(categoryElement);
}

// Yeni menü oluştur
function createNewMenu() {
  if (confirm('Yeni bir menü oluşturmak istediğinizden emin misiniz?')) {
    currentMenu = { language: currentLanguage, menu: [] };
    
    // Tüm kategorileri temizle
    document.getElementById('categories-container').innerHTML = '';
    
    // Editör alanını göster
    document.getElementById('info-alert').classList.add('d-none');
    document.getElementById('menu-editor').classList.remove('d-none');
    document.getElementById('editor-title').textContent = `${currentLanguage.toUpperCase()} Dilinde Yeni Menü Oluştur`;
    
    // İlk kategoriyi ekle
    addCategory();
  }
}

// Menüyü kaydet
async function saveMenu() {
  try {
    // UI'dan menü verilerini topla
    const menu = [];
    const categoryCards = document.querySelectorAll('.category-card');
    
    categoryCards.forEach(categoryCard => {
      const categoryName = categoryCard.querySelector('.category-name').value.trim();
      const categoryKey = categoryCard.querySelector('.category-key').value.trim() || categoryName.toLowerCase().replace(/\s+/g, '-');
      const categoryImage = categoryCard.querySelector('.category-image').value.trim();
      
      if (!categoryName) return; // Boş kategorileri atla
      
      // Ürünleri topla
      const items = [];
      const itemCards = categoryCard.querySelectorAll('.item-card');
      
      itemCards.forEach(itemCard => {
        const itemName = itemCard.querySelector('.item-name').value.trim();
        const itemPrice = itemCard.querySelector('.item-price').value.trim();
        
        if (!itemName || !itemPrice) return; // Boş ürünleri atla
        
        items.push({
          name: itemName,
          price: itemPrice,
          description: itemCard.querySelector('.item-description').value.trim(),
          image: itemCard.querySelector('.item-image').value.trim()
        });
      });
      
      if (items.length > 0) {
        menu.push({
          key: categoryKey,
          name: categoryName,
          image: categoryImage,
          items: items
        });
      }
    });
    
    if (menu.length === 0) {
      showAlert('Kaydedilecek kategori ve ürün bulunamadı!', 'warning');
      return;
    }
    
    // API'ya gönder
    const response = await fetch(`/api/admin/menu/${currentLanguage}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ menu })
    });
    
    if (!response.ok) {
      throw new Error(`Menü kaydedilemedi: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (data.success) {
      showAlert(`${currentLanguage.toUpperCase()} dilindeki menü başarıyla kaydedildi!`, 'success');
      
      // Menüyü yeniden yükle
      loadMenu(currentLanguage);
    } else {
      throw new Error(data.message || 'Bilinmeyen bir hata oluştu');
    }
  } catch (error) {
    showAlert('Menü kaydedilirken hata oluştu: ' + error.message, 'danger');
  }
}

// Menüyü sil
async function deleteMenu() {
  if (!confirm(`${currentLanguage.toUpperCase()} dilindeki menüyü silmek istediğinizden emin misiniz? Bu işlem geri alınamaz!`)) {
    return;
  }
  
  try {
    const response = await fetch(`/api/admin/menu/${currentLanguage}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      throw new Error(`Menü silinemedi: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (data.success) {
      showAlert(`${currentLanguage.toUpperCase()} dilindeki menü başarıyla silindi!`, 'success');
      
      // UI'ı temizle
      document.getElementById('categories-container').innerHTML = '';
      document.getElementById('menu-editor').classList.add('d-none');
      document.getElementById('info-alert').classList.remove('d-none');
      document.getElementById('info-alert').innerHTML = `<i class="fas fa-info-circle me-2"></i> ${currentLanguage.toUpperCase()} dilindeki menü silindi. Yeni bir menü oluşturabilirsiniz.`;
      
      currentMenu = null;
    } else {
      throw new Error(data.message || 'Bilinmeyen bir hata oluştu');
    }
  } catch (error) {
    showAlert('Menü silinirken hata oluştu: ' + error.message, 'danger');
  }
}

// Bildirim göster
function showAlert(message, type = 'info') {
  // Varolan alertleri temizle
  const existingAlerts = document.querySelectorAll('.alert-floating');
  existingAlerts.forEach(alert => alert.remove());
  
  // Yeni alert oluştur
  const alertDiv = document.createElement('div');
  alertDiv.className = `alert alert-${type} alert-floating`;
  alertDiv.innerHTML = `
    <div>${message}</div>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  `;
  
  // Alert'i sayfaya ekle
  document.body.appendChild(alertDiv);
  
  // 5 saniye sonra otomatik kapat
  setTimeout(() => {
    alertDiv.classList.add('fade-out');
    setTimeout(() => alertDiv.remove(), 500);
  }, 5000);
} 