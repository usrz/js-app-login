module.exports = function(grunt) {

  /* Grunt initialization */
  grunt.initConfig({
    simplemocha: {
      all: {
        src: ['test/**/*.test.js']
      }
    }
  });

  /* Load our plugins */
  grunt.loadNpmTasks('grunt-simple-mocha');

  /* Default tasks */
  grunt.registerTask('default', ['simplemocha']);

};
