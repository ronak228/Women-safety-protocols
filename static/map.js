// Initialize the map
var map = L.map('map').setView([20.347997, 85.804457], 14);

// Load the map tiles from OpenStreetMap
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors'
}).addTo(map);

// Define hotspot locations
var redZones = [
    { lat: 20.347997, lng: 85.804457, radius: 120 },
    { lat: 20.3436563, lng: 85.8034403, radius: 120 },
    { lat: 20.339621, lng: 85.8067146, radius: 120 },
    { lat: 20.3433443, lng: 85.8082124, radius: 120 },
    { lat: 20.348478, lng: 85.8054324, radius: 120 },
    { lat: 20.3926469, lng: 85.8239702, radius: 120 },
    { lat: 20.340056, lng: 85.808694, radius: 120 }
];

// Add hotspot locations (red zones) to the map
redZones.forEach(function(zone) {
    L.circle([zone.lat, zone.lng], {
        color: 'red',
        fillColor: '#f03',
        fillOpacity: 0.5,
        radius: zone.radius
    }).addTo(map);

    L.marker([zone.lat, zone.lng]).addTo(map)
        .bindPopup('Hotspot Location')
        .openPopup();
});

// Function to show a toast notification
function showToast(message) {
    var toast = document.createElement('div');
    toast.className = 'toast show';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        document.body.removeChild(toast);
    }, 4000);
}

// Function to request location permission
function requestLocationPermission() {
    if (navigator.geolocation) {
        // Request permission with high accuracy
        navigator.geolocation.getCurrentPosition(
            function(position) {
                var lat = position.coords.latitude;
                var lng = position.coords.longitude;

                // Add the user's marker to the map
                L.marker([lat, lng]).addTo(map)
                    .bindPopup('Your location')
                    .openPopup();

                // Check if user is inside any red zone
                redZones.forEach(function(zone) {
                    var distance = map.distance([lat, lng], [zone.lat, zone.lng]);
                    if (distance < zone.radius) {
                        showToast('Alert: You are in a Red Zone!');
                    }
                });
            },
            function(error) {
                showToast('Error: ' + error.message);
            },
            {
                enableHighAccuracy: true,
                timeout: 5000,
                maximumAge: 0
            }
        );
    } else {
        showToast('Geolocation is not supported by this browser.');
    }
}

// Add a button to request location permission
var locationButton = L.control({position: 'bottomright'});
locationButton.onAdd = function(map) {
    var div = L.DomUtil.create('div', 'leaflet-bar leaflet-control');
    div.innerHTML = '<button onclick="requestLocationPermission()" style="background-color: white; padding: 5px 10px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer;">Share Location</button>';
    return div;
};
locationButton.addTo(map);

// Request location permission when the page loads
document.addEventListener('DOMContentLoaded', function() {
    requestLocationPermission();
}); 