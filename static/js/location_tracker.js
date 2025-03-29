let map;
let locationUpdateInterval;
const UPDATE_INTERVAL = 5 * 60 * 1000; // Update every 5 minutes

// Initialize the map
function initMap() {
    map = L.map('map').setView([20.5937, 78.9629], 5); // Default center of India
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors'
    }).addTo(map);
}

// Start location tracking
function startLocationTracking() {
    // Request permission for location tracking
    if ("geolocation" in navigator) {
        // Get initial location
        updateLocation();
        
        // Set up periodic location updates
        locationUpdateInterval = setInterval(updateLocation, UPDATE_INTERVAL);
    } else {
        alert("Geolocation is not supported by your browser");
    }
}

// Update user's location
function updateLocation() {
    navigator.geolocation.getCurrentPosition(
        function(position) {
            const latitude = position.coords.latitude;
            const longitude = position.coords.longitude;
            
            // Send location to server
            fetch('/update_location', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    latitude: latitude,
                    longitude: longitude
                })
            })
            .then(response => response.json())
            .then(data => {
                if (!data.success) {
                    console.error('Failed to update location:', data.message);
                }
            })
            .catch(error => {
                console.error('Error updating location:', error);
            });
        },
        function(error) {
            console.error('Error getting location:', error);
        }
    );
}

// Display recent locations on map
function displayRecentLocations() {
    fetch('/get_recent_locations')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.locations.length > 0) {
                // Clear existing markers
                map.eachLayer((layer) => {
                    if (layer instanceof L.Marker) {
                        map.removeLayer(layer);
                    }
                });
                
                // Create a line connecting all points
                const points = data.locations.map(loc => [loc.latitude, loc.longitude]);
                L.polyline(points, {color: 'red'}).addTo(map);
                
                // Add markers for each location
                data.locations.forEach((loc, index) => {
                    const marker = L.marker([loc.latitude, loc.longitude])
                        .addTo(map)
                        .bindPopup(`Location at ${new Date(loc.timestamp).toLocaleString()}`);
                    
                    // If this is the most recent location, open its popup
                    if (index === 0) {
                        marker.openPopup();
                        map.setView([loc.latitude, loc.longitude], 15);
                    }
                });
            }
        })
        .catch(error => {
            console.error('Error getting recent locations:', error);
        });
}

// Initialize tracking when the page loads
document.addEventListener('DOMContentLoaded', function() {
    initMap();
    startLocationTracking();
    
    // Update map every minute
    setInterval(displayRecentLocations, 60000);
    displayRecentLocations(); // Initial display
}); 