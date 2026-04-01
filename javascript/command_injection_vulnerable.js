/**
 * Vulnerable JavaScript code with command injection flaws.
 * For security scanner testing only.
 */

const { exec, execSync, spawn } = require('child_process');

function pingHostVulnerable(hostname) {
    // Command injection via exec
    exec(`ping -c 4 ${hostname}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

function runCommandVulnerable(command) {
    // Command injection via execSync
    const output = execSync(command);
    console.log(output.toString());
}

function processFileVulnerable(filename) {
    // Command injection via exec with user input
    exec('cat ' + filename, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

function listFilesVulnerable(directory) {
    // Command injection via template literal
    const output = execSync(`ls -la ${directory}`);
    return output.toString();
}

function evalVulnerable(userCode) {
    // Arbitrary code execution via eval
    const result = eval(userCode);
    return result;
}

function functionConstructorVulnerable(userCode) {
    // Arbitrary code execution via Function constructor
    const fn = new Function(userCode);
    return fn();
}

function pingHostSafe(hostname) {
    // Safe version using spawn with argument array
    const child = spawn('ping', ['-c', '4', hostname]);
    child.stdout.on('data', (data) => {
        console.log(data.toString());
    });
}

function processFileSafe(filename) {
    // Safe version using spawn
    const child = spawn('cat', [filename]);
    child.stdout.on('data', (data) => {
        console.log(data.toString());
    });
}
