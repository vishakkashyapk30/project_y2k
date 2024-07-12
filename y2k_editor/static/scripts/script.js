function toggleMenu() {
    var navtexts = document.getElementsByClassName("nav-text");
    var navbutton = document.getElementById("sidebar-btn");

    for (var i = 0; i < navtexts.length; i++) {
        navtexts[i].classList.toggle("show-nav-text");
    }

    navbutton.classList.toggle('bxs-chevrons-left');
    navbutton.classList.toggle('bxs-chevrons-right');
}
