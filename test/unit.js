
module.exports = {
	tests: [],
	register: function(str_title, func_runtest) {
		this.tests.push({ title: str_title, run: func_runtest });
	},
	
	run: function() {
		var test = this.tests.shift();

		var result = {
			title: test.title
		};


		result.tests = test.run();

		return result;
	},

	run_all: function() {
		var passed = true;

		while(this.tests.length > 0) {
			var result = this.run();

			console.log('Test: ' + result.title);

			for(var i in result.tests) {

				var res = result.tests[i].result ?
					'SUCCESS' : 'FAILED';

				console.log(result.tests[i].description + ' ' + res);

				passed = passed && result.tests[i].result;
			}				
		}

		if(!passed) process.exit(1);
	},
		
	result: function(str_description, boolean_result) {
		this.description = str_description;
		this.result = boolean_result;
	}
}

