/** @file ja3_fingerprint.cc
 *
  Character delimited string token parser.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

 */

#pragma once

#include <cstddef>
#include <string_view>

class TokenStream
{
public:
  TokenStream(std::string_view view, char delimiter) : raw_content{view}, token_delimiter{delimiter} {}

  /** Get the next token in the stream.
   *
   * The string_view returned by this method will be invalidated when the
   * lifetime of the string_view used to instantiate this ends.
   *
   * @return Returns a view of the next token, otherwise an empty view.
   */
  [[nodiscard]] std::string_view
  consume()
  {
    std::size_t const token_end{this->raw_content.find(this->token_delimiter, this->token_begin)};
    std::size_t const token_size{token_end - token_begin};
    std::string_view  result{this->raw_content.substr(this->token_begin, token_size)};
    if (token_end != std::string_view::npos) {
      this->token_begin = token_end + 1;
    } else {
      this->token_begin = this->raw_content.length();
    }
    return result;
  }

  /** Skip the next token in the stream.
   */
  void
  skip()
  {
    std::size_t const token_end{this->raw_content.find(this->token_delimiter, this->token_begin)};
    this->token_begin = token_end + 1;
  }

  /** Check whether there are any tokens left.
   *
   * @return Returns true if there is another token, otherwise false.
   */
  bool
  empty() const
  {
    return this->token_begin >= this->raw_content.length();
  }

private:
  std::string_view raw_content;
  char             token_delimiter;
  std::size_t      token_begin{0};
};
