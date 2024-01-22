const rust = import('./pkg');

rust.then(m => {
  m.rand()
  m.rand()
  m.rand()
  m.rand()
  m.rand()
}).catch(console.error);
