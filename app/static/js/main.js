var notificationContainer = document.getElementById("notificationContainer");
    
if (notificationContainer.innerHTML == ''){
    notificationContainer.style.display = "none";
}else{
  console.log('Container is active')
};
setTimeout(function() {
  notificationContainer.style.display = "none"; // Remove show class to slide out
}, 3000); // Hide after 5 seconds


// When the user clicks the button, open the modal
function openModal() {
  var modal = document.getElementById("myModal");
  document.getElementById("modalPostTitle").value = document.getElementById("postTitle").value;
  document.getElementById("postTitle").value = '';
  modal.style.display = "block";
}

// When the user clicks on <span> (x), close the modal
function closeModal() {
  var modal = document.getElementById("myModal");
  modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
  var modal = document.getElementById("myModal");
  if (event.target == modal) {
    modal.style.display = "none";
  }
}