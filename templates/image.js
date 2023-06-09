function displayImage(event) {
    var input = event.target;
    if (input.files && input.files[0]) {
      var reader = new FileReader();
      reader.onload = function (e) {
        var image = document.createElement('img');
        image.src = e.target.result;
        image.classList.add('img-fluid');
        document.getElementById('image-container').innerHTML = '';
        document.getElementById('image-container').appendChild(image);
      };
      reader.readAsDataURL(input.files[0]);
    }
  }