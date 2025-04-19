// Get all audio elements on the page
const audioPlayers = document.querySelectorAll('audio');

audioPlayers.forEach(player => {
  player.addEventListener('play', () => {
    // Pause all other audio players
    audioPlayers.forEach(otherPlayer => {
      if (otherPlayer !== player) {
        otherPlayer.pause();
      }
    });

    console.log(`Playing: ${player.querySelector('source').src}`);
  });
});
