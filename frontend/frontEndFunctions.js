// these are functions that should be available to the backend

window.frontendFunctions = {
    // custom functions after this line
    start_party: function (command) {
        console.log("Starting party mode");
        function createGlitter() {
            const glitter = document.createElement('div');
            glitter.style.position = 'absolute';
            glitter.style.width = '10px';
            glitter.style.height = '10px';
            glitter.style.background = `radial-gradient(circle, ${getRandomColor()}, rgba(255, 255, 255, 0))`;
            glitter.style.borderRadius = '50%';
            glitter.style.left = Math.random() * 100 + 'vw';
            glitter.style.top = '0';
            glitter.style.opacity = '1';
            glitter.style.transition = `transform ${Math.random() * 3 + 2}s linear, opacity ${Math.random() * 3 + 2}s linear`;
            document.body.appendChild(glitter);

            requestAnimationFrame(() => {
                glitter.style.transform = 'translateY(100vh)';
                glitter.style.opacity = '0';
            });

            setTimeout(() => {
                glitter.remove();
            }, 5000);
        }
        function getRandomColor() {
            const colors = ['red', 'blue', 'green', 'yellow', 'purple', 'pink', 'orange'];
            return colors[Math.floor(Math.random() * colors.length)];
        }

        let partyEffect = setInterval(createGlitter, 10);
        // stop after 10 seconds
        setTimeout(() => {
            clearInterval(partyEffect);
        }, 10000);
    },
    get_value: function (command) {
        console.log("Starting party mode");
        return (Math.random() * 100);
    }
}


// Fetch and display latest image from scratch folder
async function updateLatestImage() {
    try {
        const res = await fetch('http://localhost:3000/api/latest-image');

        if (!res.ok) {
            console.error(`❌ HTTP ${res.status}: ${res.statusText}`);
            document.getElementById('latestImage').style.display = 'none';
            return;
        }

        const data = await res.json();
        console.log("✓ API response:", data);

        if (data.image) {
            console.log("📸 Displaying:", data.image);
            const img = document.getElementById('latestImage');
            img.src = 'http://localhost:3000' + data.image + '?' + Date.now();
            img.style.display = 'block';
        } else {
            console.log("⚠️  No image available yet");
            document.getElementById('latestImage').style.display = 'none';
        }
    } catch (err) {
        console.error('❌ Error fetching image:', err);
        document.getElementById('latestImage').style.display = 'none';
    }
}




// Update every 1 second
setInterval(updateLatestImage, 2000);

// Initial fetch
updateLatestImage();
