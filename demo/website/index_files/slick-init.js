$(document).ready(function() {
    $('#header-carousel').slick({
        lazyLoad: 'ondemand',
        slidesToShow: 1,
        slidesToScroll: 1,
        autoplay: true,
        autoplaySpeed: 3000,
        infinite: true,
        responsive: [{
            breakpoint: 768,
            settings: {
                arrows: false,
                autoplay: false
            }
        }]
    });

    $('#content-carousel').slick({
        centerMode: true,
        slidesToShow: 8,
        slidesToScroll: 2,
        variableWidth: true,
        responsive: [{
            breakpoint: 768,
            settings: {
                arrows: false,
                autoplay: false,
                centerMode: true,
                slidesToShow: 3
            }
        }]
    });

    $('#sponsors-carousel').slick({
        slidesToShow: 1,
        slidesToScroll: 1,
        autoplay: true,
        autoplaySpeed: 3000,
        infinite: true,
        arrows: false
    });
});
