// Live tracking functionality
let trackingInterval = null;
let currentMarker = null;
let trackingPath = null;
let isTracking = false;
let startTime = null;
let totalDistance = 0;
let lastPosition = null;

function startLiveTracking() {
    if (isTracking) return;
    isTracking = true;
    startTime = new Date();
    totalDistance = 0;
    lastPosition = null;

    // Show tracking info
    document.querySelector('.tracking-info').style.display = 'block';

    // Create tracking path if it doesn't exist
    if (!trackingPath) {
        trackingPath = L.polyline([], {
            color: 'blue',
            weight: 3,
            opacity: 0.7
        }).addTo(window.liveMap);
    }

    // Update location immediately and then every 5 seconds
    updateLiveLocation();
    trackingInterval = setInterval(updateLiveLocation, 5000);

    // Update UI
    document.querySelector('.tracking-status').classList.add('active');
    document.querySelector('.start-tracking').style.display = 'none';
    document.querySelector('.stop-tracking').style.display = 'block';
}

function stopLiveTracking() {
    if (!isTracking) return;
    isTracking = false;

    // Hide tracking info
    document.querySelector('.tracking-info').style.display = 'none';

    // Clear interval
    if (trackingInterval) {
        clearInterval(trackingInterval);
        trackingInterval = null;
    }

    // Update UI
    document.querySelector('.tracking-status').classList.remove('active');
    document.querySelector('.start-tracking').style.display = 'block';
    document.querySelector('.stop-tracking').style.display = 'none';

    // Reset tracking data
    startTime = null;
    lastPosition = null;
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

function updateTrackingInfo(position) {
    const { latitude, longitude } = position.coords;
    
    // Calculate distance if we have a previous position
    if (lastPosition) {
        const distance = calculateDistance(
            lastPosition.latitude,
            lastPosition.longitude,
            latitude,
            longitude
        );
        totalDistance += distance;
    }

    // Update last position
    lastPosition = { latitude, longitude };

    // Calculate duration
    const duration = startTime ? Math.floor((new Date() - startTime) / 1000) : 0;
    const hours = Math.floor(duration / 3600);
    const minutes = Math.floor((duration % 3600) / 60);
    const seconds = duration % 60;

    // Update tracking info
    const infoElement = document.querySelector('.tracking-route-info');
    infoElement.innerHTML = `
        <strong>Tracking Duration:</strong> ${hours}h ${minutes}m ${seconds}s<br>
        <strong>Total Distance:</strong> ${totalDistance.toFixed(2)} km<br>
        <strong>Current Location:</strong> ${latitude.toFixed(6)}, ${longitude.toFixed(6)}
    `;
}

function updateLiveLocation() {
    if ('geolocation' in navigator) {
        navigator.geolocation.getCurrentPosition(position => {
            const { latitude, longitude } = position.coords;

            // Update marker position
            if (!currentMarker) {
                currentMarker = L.marker([latitude, longitude]).addTo(window.liveMap);
            } else {
                currentMarker.setLatLng([latitude, longitude]);
            }

            // Add point to path
            trackingPath.addLatLng([latitude, longitude]);

            // Center map on current location
            window.liveMap.setView([latitude, longitude], window.liveMap.getZoom() || 15);

            // Update tracking info
            updateTrackingInfo(position);

            // Send location update to server
            sendLocationToServer(latitude, longitude);
        }, error => {
            console.error('Error getting location:', error);
            stopLiveTracking();
            alert('Unable to get your location. Please check your location settings.');
        });
    } else {
        alert('Geolocation is not supported by your browser');
        stopLiveTracking();
    }
}

function sendLocationToServer(latitude, longitude) {
    fetch('/api/location/update', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            latitude,
            longitude
        })
    })
    .then(response => response.json())
    .then(data => {
        if (!data.success) {
            console.error('Failed to update location:', data.message);
        }
    })
    .catch(error => {
        console.error('Error sending location update:', error);
    });
}

// Add tracking controls to the map
L.Control.TrackingStatus = L.Control.extend({
    onAdd: function(map) {
        const container = L.DomUtil.create('div', 'tracking-controls');
        container.innerHTML = `
            <div class="tracking-status">
                <div class="status-indicator"></div>
                <span>Live Tracking</span>
            </div>
            <button class="start-tracking" onclick="startLiveTracking()">
                <i class="fas fa-play"></i> Start Tracking
            </button>
            <button class="stop-tracking" onclick="stopLiveTracking()" style="display: none;">
                <i class="fas fa-stop"></i> Stop Tracking
            </button>
        `;
        return container;
    }
});

// Add the tracking controls to the map
new L.Control.TrackingStatus({ position: 'topright' }).addTo(window.liveMap);

// Add CSS styles
const style = document.createElement('style');
style.textContent = `
    .tracking-controls {
        background: white;
        padding: 10px;
        border-radius: 4px;
        box-shadow: 0 1px 5px rgba(0,0,0,0.4);
    }
    .tracking-status {
        display: flex;
        align-items: center;
        margin-bottom: 8px;
    }
    .status-indicator {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #ccc;
        margin-right: 8px;
        transition: background-color 0.3s;
    }
    .tracking-status.active .status-indicator {
        background: #4CAF50;
        animation: pulse 1.5s infinite;
    }
    .tracking-controls button {
        width: 100%;
        padding: 6px 12px;
        border: none;
        border-radius: 4px;
        background: #007bff;
        color: white;
        cursor: pointer;
        transition: background-color 0.3s;
    }
    .tracking-controls button:hover {
        background: #0056b3;
    }
    @keyframes pulse {
        0% {
            transform: scale(1);
            opacity: 1;
        }
        50% {
            transform: scale(1.2);
            opacity: 0.7;
        }
        100% {
            transform: scale(1);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style); 