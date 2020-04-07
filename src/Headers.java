/*
Copyright 2018 Eduardo Garcia Melia <wagiro@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package burpbounty;

public class Headers {

    String type;
    String match;
    String replace;
    String regex;
    String comment;

    Headers(String type, String match, String replace, String regex, String comment) {
        this.type = type;
        this.match = match;
        this.replace = replace;
        this.regex = regex;
        this.comment = comment;
    }

}
