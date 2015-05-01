const errorlog = require('errorlog');

module.exports = function(grunt) {
  grunt.option('stack', true);

  console.log(grunt.cli.options);

  if (grunt.cli.options.log === true) {
    errorlog.defaultLevel = errorlog.INFO;
  } else if (grunt.cli.options.log) {
    var level = grunt.cli.options.log.toString().toUpperCase();
    errorlog.defaultLevel = eval("errorlog." + level);
  } else {
    errorlog.defaultLevel = errorlog.OFF;
  }


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
