const rust = import('./pkg');

rust.then(m => m.test()).catch(console.error);
