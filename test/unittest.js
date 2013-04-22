
var unittests = {
	tests: [],
	register: function(str_title, func_runtest) {
		this.tests.push({ title: str_title, run: func_runtest });
	},
	
	run: function() {
		var test = this.tests.shift();

		var result = {
			title: test.title
		};


		//try
		{
			result.tests = test.run();
		}
		/*catch(e)
		{
			result.tests = [{ 
				description: 'Failed with an exception: ' + e,
				result: false
			}];
		}*/

		return result;
	}
}

function test_result(str_description, boolean_result) {
	this.description = str_description;
	this.result = boolean_result;
}
