



// addEventListener('fetch', event => {
//   console.log(event);
//   const url = new URL(event.request.url);
//   console.log(url);
//   if (url.pathname === '/test/somedata') {
//     let plaintext = [];
//     let i = 0;    
//     let canceled = false;
//     const data = new ReadableStream({
//       /*start(_controller) {
//         controller = _controller;
//       },*/
//       async pull(controller) {
//         await new Promise(resolve => setTimeout(resolve, 1000));
//         console.log(i);
//         if (i++ < 10) {
//           let randomBytes = new Uint8Array(1000);
//           randomBytes.fill(i);
//           controller.enqueue(randomBytes);
//           plaintext.push(randomBytes);
//         } else {
//           controller.close();
//         }
//       },
//       cancel() {
//         console.log('canceled!');
//       }
//     });

    
//     const response = new Response(data, {
//       headers: {
//         'Content-Type': 'application/octet-stream; charset=utf-8',
//         'Content-Disposition': 'Content-Disposition: attachment; filename=data.bin;'
//       }
//     });

//     event.respondWith(response);
//   }

// });

    