// Updated loadMenuData function to fetch menu data from MongoDB via server API

// Dile göre menüyü yükle (MongoDB'den çekiyor)
async function loadMenuData(language) {
  try {
    console.log("loadMenuData çağrıldı:", language);
    
    // API yolu oluştur - Sunucu URL'sini kendi sunucunuza göre değiştirin
    const apiUrl = `https://hotel1-backend-864359396873.europe-west3.run.app/api/menu/${language}`;
    console.log("Menü verisi API'dan yükleniyor:", apiUrl);
    
    // Timeout ile fetch kullan
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 saniyelik timeout
    
    try {
      const response = await fetch(apiUrl, { 
        signal: controller.signal 
      });
      
      clearTimeout(timeoutId); // Temizle
      
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      
      const data = await response.json();
      menuData = data;
      console.log("Menü verisi MongoDB'den yüklendi:", data.menu?.length || 0, "kategori");
      
      // Kategori tablarını ve menü öğelerini göster
      displayCategories(data.menu || []);
      
      // Arama kutusu placeholder'ını güncelle
      updateSearchPlaceholder();
    } catch (fetchError) {
      clearTimeout(timeoutId);
      console.error("Fetch error:", fetchError);
      
      if (fetchError.name === 'AbortError') {
        console.log("Fetch timeout, trying fallback language");
      }
      
      // Hata durumunda varsayılan dilde yüklemeyi dene
      if (language !== 'en') {
        console.log("Trying to load default language (en) as fallback.");
        currentLanguage = 'en';
        loadMenuData('en');
      } else {
        // Varsayılan dil de yüklenemiyorsa, bir hata mesajı göster
        console.error("Failed to load menu data, even with fallback language.");
        showErrorMessage("Failed to load menu data. Please check your connection and try again.");
      }
    }
  } catch (error) {
    console.error("Error in loadMenuData:", error);
    
    // Hata durumunda varsayılan dilde yüklemeyi dene
    if (language !== 'en') {
      console.log("Trying to load default language (en) as fallback.");
      currentLanguage = 'en';
      loadMenuData('en');
    } else {
      // Varsayılan dil de yüklenemiyorsa, bir hata mesajı göster
      showErrorMessage("Failed to load menu data. Please check your connection and try again.");
    }
  }
}

// Düzeltilmiş displayCategories fonksiyonu - undefined veya boş menu durumlarını ele alır
function displayCategories(menuData) {
  console.log("displayCategories çağrıldı", menuData?.length || 0, "kategori");
  
  const categoryTabs = document.getElementById('category-tabs');
  if (!categoryTabs) {
    console.error("category-tabs bulunamadı!");
    return;
  }
  
  categoryTabs.innerHTML = '';
  
  // Menü verisi kontrol edilir
  if (!menuData || !Array.isArray(menuData) || menuData.length === 0) {
    console.error("Menü verisi boş veya tanımsız!");
    
    // Boş menü durumunda kullanıcıya hata mesajı göster
    const errorMsg = document.createElement('div');
    errorMsg.textContent = 'Menü yüklenemedi. Lütfen daha sonra tekrar deneyin.';
    errorMsg.style.padding = '20px';
    errorMsg.style.textAlign = 'center';
    categoryTabs.appendChild(errorMsg);
    return;
  }
  
  menuCategories = menuData;
  
  // Mobil uygun kategori tablarını oluştur
  menuData.forEach((category, index) => {
    const tab = document.createElement('div');
    tab.classList.add('category-tab');
    tab.textContent = category.name;
    tab.dataset.key = category.key;
    
    if (index === 0) {
      tab.classList.add('active');
      currentCategory = category;
    }
    
    tab.addEventListener('click', () => {
      // Önceki aktif tabın sınıfını kaldır
      document.querySelectorAll('.category-tab').forEach(tab => {
        tab.classList.remove('active');
      });
      
      // Bu tabı aktif yap
      tab.classList.add('active');
      
      // Kategori ürünlerini göster
      currentCategory = category;
      renderMenuItems(category);
      
      // Arama input'unu temizle
      const searchInput = document.getElementById('search-input');
      if (searchInput) {
        searchInput.value = '';
      }
    });
    
    categoryTabs.appendChild(tab);
  });
  
  // İlk kategoriyi göster
  if (menuData.length > 0) {
    renderMenuItems(menuData[0]);
  }
} 