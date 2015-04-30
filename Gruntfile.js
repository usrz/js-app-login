const errorlog = require('errorlog');

module.exports = function(grunt) {
  errorlog.defaultLevel = errorlog.ALL;
  errorlog.defaultLog = grunt.log.debug;

  grunt.option('stack', true);

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
