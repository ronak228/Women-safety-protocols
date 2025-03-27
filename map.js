function initializeMap() {
    // Initialize the map
    const map = L.map('map').setView([28.6139, 77.209], 13);  // Coordinates for New Delhi, India

    // Load map tiles from OpenStreetMap
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
    }).addTo(map);

    // Example red zone (hotspot) coordinates
    const redZone = L.circle([28.615, 77.215], {
        color: 'red',
        fillColor: '#f03',
        fillOpacity: 0.5,  
        radius: 500  // Radius in meters
    }).addTo(map);

    // Real-time user location tracking
    function trackUserLocation() {
        if (navigator.geolocation) {
            navigator.geolocation.watchPosition(function(position) {
                const userLat = position.coords.latitude;
                const userLon = position.coords.longitude;

                // Place a marker for the user's current location
                const userMarker = L.marker([userLat, userLon]).addTo(map)
                    .bindPopup("You are here")
                    .openPopup();

                // Check if the user is in the red zone
                const distanceToRedZone = map.distance([userLat, userLon], redZone.getLatLng());

                // If user enters the red zone, show alert
                if (distanceToRedZone < redZone.getRadius()) {
                    document.getElementById('alert-box').style.display = 'block';
                    document.getElementById('alert-box').innerHTML = "Alert: You are in a Red Zone!";
                } else {
                    document.getElementById('alert-box').style.display = 'none';
                }
            }, function(error) {
                alert("Error getting location: " + error.message);
            });
        } else {
            alert("Geolocation is not supported by this browser.");
        }
    }

    // Initialize the user location tracking
    trackUserLocation();
}

window.onload = initializeMap;
