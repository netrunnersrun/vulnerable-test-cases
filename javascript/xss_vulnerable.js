/**
 * Vulnerable JavaScript code with XSS flaws.
 * For security scanner testing only.
 */

function displaySearchResults(query) {
    // DOM-based XSS via innerHTML
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `<h1>Results for: ${query}</h1>`;
}

function greetUser(username) {
    // DOM-based XSS via innerHTML
    const greeting = document.getElementById('greeting');
    greeting.innerHTML = "<h1>Welcome " + username + "</h1>";
}

function showMessage(message) {
    // DOM-based XSS via outerHTML
    const messageDiv = document.getElementById('message');
    messageDiv.outerHTML = `<div class="alert">${message}</div>`;
}

function renderContent(content) {
    // DOM-based XSS via document.write
    document.write(content);
}

function updatePage(html) {
    // DOM-based XSS via document.writeln
    document.writeln(html);
}

function displayUserData(data) {
    // jQuery XSS
    $('#user-data').html(data);
}

function reactDangerousComponent(userContent) {
    // React dangerouslySetInnerHTML
    return <div dangerouslySetInnerHTML={{__html: userContent}} />;
}

function displaySearchResultsSafe(query) {
    // Safe version using textContent
    const resultsDiv = document.getElementById('results');
    resultsDiv.textContent = `Results for: ${query}`;
}

function greetUserSafe(username) {
    // Safe version using textContent
    const greeting = document.getElementById('greeting');
    greeting.textContent = `Welcome ${username}`;
}
