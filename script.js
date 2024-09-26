let gaugeChart;

// Initialize the gauge chart
function initializeGauge() {
    const ctx = document.getElementById('entropyGauge').getContext('2d');
    gaugeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 100], // Initial data for the gauge
                backgroundColor: ['#FF0000', '#e0e0e0'], // Red color for the initial value
                borderWidth: 0
            }]
        },
        options: {
            circumference: 180, // Display half circle
            rotation: -90, // Rotate to start from bottom
            cutout: '75%',
            plugins: {
                tooltip: { enabled: false },
                legend: { display: false }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// Update the gauge chart
function updateGauge(entropy) {
    let maxEntropy = 128; // Maximum value for the gauge
    let percentage = Math.min((entropy / maxEntropy) * 100, 100);
    let color = getGaugeColor(percentage);

    gaugeChart.data.datasets[0].data[0] = percentage;
    gaugeChart.data.datasets[0].data[1] = 100 - percentage;
    gaugeChart.data.datasets[0].backgroundColor[0] = color;
    gaugeChart.update();
}

// Get gauge color based on entropy percentage
function getGaugeColor(percentage) {
    if (percentage < 28) return '#FF0000'; // Red for weak
    if (percentage < 60) return '#FFA500'; // Orange for reasonable
    if (percentage < 100) return '#00FF00'; // Green for strong
    return '#008000'; // Dark green for very strong
}

function calculateEntropy() {
    const password = document.getElementById('passwordInput').value;
    let entropy = calculatePasswordEntropy(password);
    let feedback = getFeedback(entropy);

    document.getElementById('result').innerText = `Entropy: ${entropy.toFixed(2)} bits`;
    document.getElementById('feedback').innerText = `Feedback: ${feedback}`;
    updateGauge(entropy); // Update the gauge chart with the new entropy value

    checkIfPwned(password); // Check if the password has been pwned
}

// Function to calculate SHA-1 hash
async function sha1(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Function to check if a password has been pwned using the Have I Been Pwned API
async function checkIfPwned(password) {
    if (!password) return;

    // Calculate SHA-1 hash of the password
    const hash = await sha1(password);
    const prefix = hash.substring(0, 5).toUpperCase();
    const suffix = hash.substring(5).toUpperCase();

    // Pwned Passwords API URL with prefix
    const url = `https://api.pwnedpasswords.com/range/${prefix}`;

    try {
        const response = await fetch(url);
        const data = await response.text();

        // Check if suffix is present in the response
        const lines = data.split('\n');
        let pwnedCount = 0;
        for (const line of lines) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix === suffix) {
                pwnedCount = parseInt(count, 10);
                break;
            }
        }

        // Display the result to the user
        if (pwnedCount > 0) {
            document.getElementById('pwnedResult').innerText = `Pwned Check: This password has been found ${pwnedCount} times in data breaches. Consider using a different password.`;
        } else {
            document.getElementById('pwnedResult').innerText = "Pwned Check: This password has not been found in any data breaches.";
        }
    } catch (error) {
        console.error('Error checking if password is pwned:', error);
        document.getElementById('pwnedResult').innerText = "Pwned Check: Unable to check at this time. Please try again later.";
    }
}

function calculatePasswordEntropy(password) {
    if (password.length === 0) return 0;

    let charsetSize = getCharsetSize(password);
    let shannonEntropy = password.length * Math.log2(charsetSize);
    let patternPenalty = getPatternPenalty(password);
    let pcfgPenalty = getPCFGPenalty(password);

    let finalEntropy = shannonEntropy - patternPenalty - pcfgPenalty;
    return finalEntropy > 0 ? finalEntropy : 0; // Entropy should not be negative
}

function getCharsetSize(password) {
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    return charsetSize;
}

function getPatternPenalty(password) {
    let patterns = [/12345/, /password/, /qwerty/, /abcde/, /[A-Za-z]{3,}/, /[0-9]{3,}/];
    let penalty = 0;

    patterns.forEach(pattern => {
        if (pattern.test(password)) {
            penalty += 10; // Subtract 10 bits for each common pattern found
        }
    });

    return penalty;
}

function getPCFGPenalty(password) {
    let segments = password.match(/[a-zA-Z]+|[0-9]+|[^a-zA-Z0-9]+/g);
    let penalty = 0;

    if (segments) {
        segments.forEach(segment => {
            if (isDictionaryWord(segment)) {
                penalty += 10;
            }

            if (/[0-9]{2,}/.test(segment)) {
                penalty += 5; // Common number sequences
            }
        });
    }

    return penalty;
}

function isDictionaryWord(segment) {
    const commonWords = ["password", "admin", "user", "test"];
    return commonWords.includes(segment.toLowerCase());
}

function getFeedback(entropy) {
    if (entropy < 28) {
        return "Very Weak - Consider using a longer and more complex password.";
    } else if (entropy < 36) {
        return "Weak - Add more variety to your password.";
    } else if (entropy < 60) {
        return "Reasonable - Your password is decent but could be stronger.";
    } else if (entropy < 128) {
        return "Strong - Your password is strong enough for most purposes.";
    } else {
        return "Very Strong - Excellent choice of password.";
    }
}

// Initialize the gauge when the page loads
window.onload = initializeGauge;
